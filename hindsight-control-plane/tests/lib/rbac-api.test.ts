import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { rbac } from "@/lib/rbac-api";

vi.mock("sonner", () => ({ toast: { error: vi.fn(), warning: vi.fn() } }));

describe("rbac client", () => {
  let fetchSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    fetchSpy = vi.spyOn(globalThis, "fetch");
  });
  afterEach(() => {
    fetchSpy.mockRestore();
  });

  it("rbac.putGrant sends the grant to /api/rbac/banks/{id}/grants", async () => {
    const access = { bank_id: "a/b", grants: [] };
    fetchSpy.mockResolvedValueOnce(Response.json(access));
    const grant = { principal_type: "team" as const, principal_id: "t1", role: "writer" as const };

    await expect(rbac.putGrant("a/b", grant)).resolves.toEqual(access);

    const [url, init] = fetchSpy.mock.calls[0];
    expect(url).toBe("/api/rbac/banks/a%2Fb/grants");
    expect(init?.method).toBe("PUT");
    expect(JSON.parse(String(init?.body))).toEqual(grant);
  });

  it("rbac.deleteGrant uses /grants/{type}/{id} and resolves on a 204", async () => {
    fetchSpy.mockResolvedValueOnce(new Response(null, { status: 204 }));

    await expect(rbac.deleteGrant("b1", "principal", "u1")).resolves.toBeUndefined();

    const [url, init] = fetchSpy.mock.calls[0];
    expect(url).toBe("/api/rbac/banks/b1/grants/principal/u1");
    expect(init?.method).toBe("DELETE");
  });
});
