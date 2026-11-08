import { describe, expect, it } from "vitest";
import { openSession, sealSession, type UserSession } from "@/lib/auth/user-session";

const SECRET = "a-session-secret-that-is-at-least-32-chars";
const now = () => Math.floor(Date.now() / 1000);

function session(overrides: Partial<UserSession> = {}): UserSession {
  return {
    v: 1,
    kind: "token",
    cred: "hsp_abc",
    credExp: now() + 3600,
    exp: now() + 3600,
    user: { id: "u1", name: "Alice", email: "alice@firefly.ai", kind: "user", is_admin: false },
    ...overrides,
  };
}

describe("user session cookie", () => {
  it("round-trips", async () => {
    const s = session({ kind: "oidc", refresh: "r1" });
    expect(await openSession(await sealSession(s, SECRET), SECRET)).toEqual(s);
  });

  it("rejects a tampered value", async () => {
    const sealed = await sealSession(session(), SECRET);
    const flipped = sealed.slice(0, 20) + (sealed[20] === "A" ? "B" : "A") + sealed.slice(21);
    expect(await openSession(flipped, SECRET)).toBeNull();
  });

  it("rejects another secret", async () => {
    const sealed = await sealSession(session(), SECRET);
    expect(await openSession(sealed, SECRET + "-other")).toBeNull();
  });

  it("rejects an expired session", async () => {
    const sealed = await sealSession(session({ exp: now() - 1 }), SECRET);
    expect(await openSession(sealed, SECRET)).toBeNull();
  });

  it("rejects garbage and absence", async () => {
    expect(await openSession("not-a-cookie", SECRET)).toBeNull();
    expect(await openSession("", SECRET)).toBeNull();
    expect(await openSession(undefined, SECRET)).toBeNull();
  });
});
