import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { installDataplaneAuth } from "@/lib/auth/dataplane-auth";
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
  let current: UserSession | null;

  beforeEach(() => {
    seen = [];
    original = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      seen.push(new Request(input, init));
      return new Response("{}");
    }) as typeof fetch;
    current = SESSION;
    installDataplaneAuth(DATAPLANE, async () => current);
  });
  afterEach(() => {
    globalThis.fetch = original;
    delete (globalThis as Record<symbol, unknown>)[Symbol.for("hindsight.cp.unwrappedFetch")];
    vi.restoreAllMocks();
  });

  it("sends the signed-in user's credential to the dataplane", async () => {
    await fetch(`${DATAPLANE}/v1/default/banks`, { headers: { Authorization: "Bearer shared-key" } });
    expect(seen[0].headers.get("authorization")).toBe("Bearer hsp_alice");
  });

  it("strips any credential when nobody is signed in", async () => {
    current = null;
    await fetch(`${DATAPLANE}/v1/default/banks`, { headers: { Authorization: "Bearer shared-key" } });
    expect(seen[0].headers.get("authorization")).toBeNull();
  });

  it("leaves other hosts alone", async () => {
    await fetch("https://issuer.test/token", { headers: { Authorization: "Basic abc" } });
    expect(seen[0].headers.get("authorization")).toBe("Basic abc");
  });

  it("handles Request inputs and keeps the method and body", async () => {
    await fetch(new Request(`${DATAPLANE}/v1/default/banks/b/memories`, { method: "POST", body: "{}" }));
    expect(seen[0].method).toBe("POST");
    expect(await seen[0].text()).toBe("{}");
    expect(seen[0].headers.get("authorization")).toBe("Bearer hsp_alice");
  });

  it("does not match a host that merely starts with the dataplane URL", async () => {
    await fetch("http://dataplane.evil.test:8888/x", { headers: { Authorization: "Bearer keep" } });
    expect(seen[0].headers.get("authorization")).toBe("Bearer keep");
  });
});
