import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/hindsight-client", () => ({ DATAPLANE_URL: "http://dataplane" }));

import { GET as config } from "@/app/api/auth/config/route";
import { GET as me } from "@/app/api/auth/me/route";
import { POST as logout } from "@/app/api/auth/logout/route";
import { GET as oidcCallback } from "@/app/api/auth/oidc/callback/route";
import { GET as oidcStart } from "@/app/api/auth/oidc/start/route";
import { POST as tokenLogin } from "@/app/api/auth/token-login/route";
import { OIDC_STATE_COOKIE } from "@/lib/auth/rbac-login";
import { USER_SESSION_COOKIE, openSession, sealSession } from "@/lib/auth/user-session";

const SECRET = "rbac-session-secret-at-least-32-chars!!";
const ISSUER = "https://issuer.test";
const ME = { id: "u1", kind: "user", email: "alice@firefly.ai", name: "Alice", is_admin: false };

function idToken(exp: number): string {
  const enc = (o: object) => btoa(JSON.stringify(o)).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
  return `${enc({ alg: "RS256" })}.${enc({ exp })}.sig`;
}

/** A fake dataplane + issuer: /ext/rbac/me accepts `good-token` and `id-token-*`. */
function fakeNetwork() {
  const calls: { url: string; init?: RequestInit }[] = [];
  const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
    calls.push({ url, init });
    if (url.endsWith("/.well-known/openid-configuration")) {
      return Response.json({ authorization_endpoint: `${ISSUER}/authorize`, token_endpoint: `${ISSUER}/token` });
    }
    if (url === `${ISSUER}/token`) {
      return Response.json({ id_token: idToken(Math.floor(Date.now() / 1000) + 3600), refresh_token: "r1" });
    }
    if (url === "http://dataplane/ext/rbac/me") {
      const auth = new Headers(init?.headers).get("authorization") ?? "";
      return auth === "Bearer good-token" || auth.startsWith("Bearer eyJ")
        ? Response.json(ME)
        : Response.json({ detail: "nope" }, { status: 401 });
    }
    throw new Error(`unexpected fetch ${url}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  return calls;
}

describe("rbac auth routes", () => {
  beforeEach(() => {
    vi.stubEnv("HINDSIGHT_CP_AUTH_MODE", "rbac");
    vi.stubEnv("HINDSIGHT_CP_SESSION_SECRET", SECRET);
    vi.stubEnv("HINDSIGHT_CP_OIDC_ISSUER", ISSUER);
    vi.stubEnv("HINDSIGHT_CP_OIDC_CLIENT_ID", "cid");
    vi.stubEnv("HINDSIGHT_CP_OIDC_CLIENT_SECRET", "csecret");
  });
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  it("describes the login options", async () => {
    expect(await (await config()).json()).toEqual({ mode: "rbac", google: true, tokenLogin: true });
    vi.stubEnv("HINDSIGHT_CP_TOKEN_LOGIN", "false");
    vi.stubEnv("HINDSIGHT_CP_OIDC_CLIENT_SECRET", "");
    expect(await (await config()).json()).toEqual({ mode: "rbac", google: false, tokenLogin: false });
  });

  it("signs in with a valid API token", async () => {
    fakeNetwork();
    const res = await tokenLogin(
      new NextRequest("http://localhost/api/auth/token-login", { method: "POST", body: '{"token":"good-token"}' })
    );
    expect(res.status).toBe(200);
    const session = await openSession(res.cookies.get(USER_SESSION_COOKIE)?.value, SECRET);
    expect(session?.cred).toBe("good-token");
    expect(session?.user.name).toBe("Alice");
  });

  it("refuses an invalid API token", async () => {
    fakeNetwork();
    const res = await tokenLogin(
      new NextRequest("http://localhost/api/auth/token-login", { method: "POST", body: '{"token":"bad"}' })
    );
    expect(res.status).toBe(401);
    expect(res.cookies.get(USER_SESSION_COOKIE)).toBeUndefined();
  });

  it("refuses token login when it is switched off", async () => {
    vi.stubEnv("HINDSIGHT_CP_TOKEN_LOGIN", "false");
    fakeNetwork();
    const res = await tokenLogin(
      new NextRequest("http://localhost/api/auth/token-login", { method: "POST", body: '{"token":"good-token"}' })
    );
    expect(res.status).toBe(404);
  });

  it("starts OIDC with PKCE and a state cookie", async () => {
    fakeNetwork();
    const res = await oidcStart(new NextRequest("http://localhost:9999/api/auth/oidc/start?returnTo=%2Fbanks%2Fa"));
    expect(res.status).toBe(307);
    const location = new URL(res.headers.get("location")!);
    expect(location.origin + location.pathname).toBe(`${ISSUER}/authorize`);
    expect(location.searchParams.get("client_id")).toBe("cid");
    expect(location.searchParams.get("code_challenge_method")).toBe("S256");
    expect(location.searchParams.get("redirect_uri")).toBe("http://localhost:9999/api/auth/oidc/callback");
    expect(location.searchParams.get("state")).toBeTruthy();
    expect(res.cookies.get(OIDC_STATE_COOKIE)?.value).toBeTruthy();
  });

  async function startedFlow() {
    const start = await oidcStart(new NextRequest("http://localhost:9999/api/auth/oidc/start?returnTo=%2Fbanks%2Fa"));
    const state = new URL(start.headers.get("location")!).searchParams.get("state")!;
    return { state, cookie: start.cookies.get(OIDC_STATE_COOKIE)!.value };
  }

  it("completes OIDC: code exchange, session, back to returnTo", async () => {
    const calls = fakeNetwork();
    const { state, cookie } = await startedFlow();
    const req = new NextRequest(`http://localhost:9999/api/auth/oidc/callback?code=c1&state=${state}`);
    req.cookies.set(OIDC_STATE_COOKIE, cookie);
    const res = await oidcCallback(req);
    expect(res.headers.get("location")).toBe("http://localhost:9999/banks/a");
    const session = await openSession(res.cookies.get(USER_SESSION_COOKIE)?.value, SECRET);
    expect(session?.kind).toBe("oidc");
    expect(session?.refresh).toBe("r1");
    expect(session?.user.email).toBe("alice@firefly.ai");
    const tokenCall = calls.find((c) => c.url === `${ISSUER}/token`)!;
    expect(String(tokenCall.init?.body)).toContain("code_verifier=");
  });

  it("rejects a callback whose state does not match", async () => {
    fakeNetwork();
    const { cookie } = await startedFlow();
    const req = new NextRequest("http://localhost:9999/api/auth/oidc/callback?code=c1&state=forged");
    req.cookies.set(OIDC_STATE_COOKIE, cookie);
    const res = await oidcCallback(req);
    expect(res.headers.get("location")).toBe("http://localhost:9999/login?error=sso");
    expect(res.cookies.get(USER_SESSION_COOKIE)?.value ?? "").toBe("");
  });

  it("rejects a callback with no state cookie", async () => {
    fakeNetwork();
    const res = await oidcCallback(new NextRequest("http://localhost:9999/api/auth/oidc/callback?code=c1&state=x"));
    expect(res.headers.get("location")).toBe("http://localhost:9999/login?error=sso");
  });

  it("reports the signed-in user and clears the session on logout", async () => {
    const now = Math.floor(Date.now() / 1000);
    const sealed = await sealSession(
      { v: 1, kind: "token", cred: "good-token", credExp: now + 60, exp: now + 60, user: { ...ME } },
      SECRET
    );
    const req = new NextRequest("http://localhost/api/auth/me");
    req.cookies.set(USER_SESSION_COOKIE, sealed);
    expect((await (await me(req)).json()).user.name).toBe("Alice");
    expect((await me(new NextRequest("http://localhost/api/auth/me"))).status).toBe(401);

    const out = await logout(new NextRequest("http://localhost/api/auth/logout", { method: "POST" }));
    expect(out.cookies.get(USER_SESSION_COOKIE)?.value).toBe("");
  });
});
