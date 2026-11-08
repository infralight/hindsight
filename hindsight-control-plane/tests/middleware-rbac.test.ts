import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest, NextResponse } from "next/server";
import { middleware } from "@/middleware";
import { USER_SESSION_COOKIE, openSession, sealSession, type UserSession } from "@/lib/auth/user-session";

vi.mock("next-intl/middleware", () => ({ default: () => () => NextResponse.next() }));

const SECRET = "rbac-session-secret-at-least-32-chars!!";
const ISSUER = "https://issuer.test";
const now = () => Math.floor(Date.now() / 1000);

function idToken(exp: number): string {
  const enc = (o: object) => btoa(JSON.stringify(o)).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
  return `${enc({ alg: "RS256" })}.${enc({ exp, email: "a@firefly.ai" })}.sig`;
}

function session(overrides: Partial<UserSession> = {}): UserSession {
  return {
    v: 1,
    kind: "token",
    cred: "hsp_x",
    credExp: now() + 3600,
    exp: now() + 3600,
    user: { id: "u1", name: "Alice", email: "a@firefly.ai", kind: "user", is_admin: false },
    ...overrides,
  };
}

async function request(path: string, s?: UserSession) {
  const req = new NextRequest(new URL(path, "http://localhost:9999"));
  if (s) req.cookies.set(USER_SESSION_COOKIE, await sealSession(s, SECRET));
  return middleware(req);
}

describe("middleware in rbac mode", () => {
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

  it("sends a page visit without a session to /login", async () => {
    const res = await request("/banks/x");
    expect(res.status).toBe(307);
    expect(res.headers.get("location")).toBe("http://localhost:9999/login?returnTo=%2Fbanks%2Fx");
  });

  it("answers an API call without a session with a session-required 401", async () => {
    const res = await request("/api/banks");
    expect(res.status).toBe(401);
    expect(res.headers.get("x-hindsight-session-required")).toBe("1");
  });

  it("lets a signed-in API call through", async () => {
    const res = await request("/api/banks", session());
    expect(res.status).toBe(200);
  });

  it("sends a signed-in visit to /login on to its returnTo", async () => {
    const res = await request("/login?returnTo=%2Fbanks%2Fa", session());
    expect(res.headers.get("location")).toBe("http://localhost:9999/banks/a");
  });

  it("keeps the auth routes public", async () => {
    expect((await request("/api/auth/config")).status).toBe(200);
  });

  it("refreshes an expired ID token and re-seals the session", async () => {
    const fresh = idToken(now() + 3600);
    const fetchMock = vi.fn(async (url: string) => {
      if (url.endsWith("/.well-known/openid-configuration")) {
        return Response.json({ authorization_endpoint: `${ISSUER}/auth`, token_endpoint: `${ISSUER}/token` });
      }
      return Response.json({ id_token: fresh });
    });
    vi.stubGlobal("fetch", fetchMock);

    const expired = session({ kind: "oidc", cred: idToken(now() - 10), credExp: now() - 10, refresh: "r1" });
    const res = await request("/api/banks", expired);
    expect(res.status).toBe(200);
    const cookie = res.cookies.get(USER_SESSION_COOKIE)?.value;
    const reopened = await openSession(cookie, SECRET);
    expect(reopened?.cred).toBe(fresh);
    expect(reopened?.refresh).toBe("r1");
  });

  it("treats an expired ID token with no refresh token as signed out", async () => {
    const expired = session({ kind: "oidc", cred: idToken(now() - 10), credExp: now() - 10 });
    expect((await request("/api/banks", expired)).status).toBe(401);
    expect((await request("/banks", expired)).headers.get("location")).toContain("/login");
  });

  it("treats a tampered cookie as signed out", async () => {
    const req = new NextRequest(new URL("/api/banks", "http://localhost:9999"));
    req.cookies.set(USER_SESSION_COOKIE, "tampered-value");
    expect((await middleware(req)).status).toBe(401);
  });
});
