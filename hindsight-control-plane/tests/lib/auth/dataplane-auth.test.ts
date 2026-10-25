import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { installDataplaneAuth, rawFetch } from "@/lib/auth/dataplane-auth";
import type { UserSession } from "@/lib/auth/user-session";

const DATAPLANE = "http://dataplane:8888";

const SESSION: UserSession = {
  v: 1,
  kind: "token",
  cred: "hsp_alice",
  credExp: 9e9,
  exp: 9e9,
  user: { id: "u1", name: "Alice", email: null, kind: "user", is_admin: false },
};

describe("installDataplaneAuth", () => {
  let seen: Request[];
  let original: typeof fetch;
  let recorder: typeof fetch;
  let current: UserSession | null;

  beforeEach(() => {
    seen = [];
    original = globalThis.fetch;
    recorder = (async (input: RequestInfo | URL, init?: RequestInit) => {
      seen.push(new Request(input, init));
      return new Response("{}");
    }) as typeof fetch;
    globalThis.fetch = recorder;
    current = SESSION;
    installDataplaneAuth(DATAPLANE, async () => current);
  });
  afterEach(() => {
    globalThis.fetch = original;
    delete (globalThis as Record<symbol, unknown>)[Symbol.for("hindsight.cp.unwrappedFetch")];
    delete (globalThis as Record<symbol, unknown>)[Symbol.for("next-patch")];
    vi.restoreAllMocks();
  });

  // What `next dev` does on every server recompile (router-server.js resetFetch).
  const nextDevResetsFetch = () => {
    globalThis.fetch = recorder;
    (globalThis as Record<symbol, unknown>)[Symbol.for("next-patch")] = false;
  };

  it("keeps sending the user's credential after next dev resets fetch", async () => {
    nextDevResetsFetch();
    await fetch(`${DATAPLANE}/v1/default/banks`);
    expect(seen[0].headers.get("authorization")).toBe("Bearer hsp_alice");
  });

  it("still hands login the unwrapped fetch after a reset", async () => {
    nextDevResetsFetch();
    expect(rawFetch()).toBe(recorder);
  });

  it("wraps only once when the reset flag is cleared again without a new fetch", async () => {
    nextDevResetsFetch();
    (globalThis as Record<symbol, unknown>)[Symbol.for("next-patch")] = false;
    expect(rawFetch()).toBe(recorder);
  });

  it("sends the signed-in user's credential to the dataplane", async () => {
    await fetch(`${DATAPLANE}/v1/default/banks`, {
      headers: { Authorization: "Bearer shared-key" },
    });
    expect(seen[0].headers.get("authorization")).toBe("Bearer hsp_alice");
  });

  it("strips any credential when nobody is signed in", async () => {
    current = null;
    await fetch(`${DATAPLANE}/v1/default/banks`, {
      headers: { Authorization: "Bearer shared-key" },
    });
    expect(seen[0].headers.get("authorization")).toBeNull();
  });

  it("leaves other hosts alone", async () => {
    await fetch("https://issuer.test/token", { headers: { Authorization: "Basic abc" } });
    expect(seen[0].headers.get("authorization")).toBe("Basic abc");
  });

  it("handles Request inputs and keeps the method and body", async () => {
    await fetch(
      new Request(`${DATAPLANE}/v1/default/banks/b/memories`, { method: "POST", body: "{}" })
    );
    expect(seen[0].method).toBe("POST");
    expect(await seen[0].text()).toBe("{}");
    expect(seen[0].headers.get("authorization")).toBe("Bearer hsp_alice");
  });

  it("does not match a host that merely starts with the dataplane URL", async () => {
    await fetch("http://dataplane.evil.test:8888/x", { headers: { Authorization: "Bearer keep" } });
    expect(seen[0].headers.get("authorization")).toBe("Bearer keep");
  });
});
