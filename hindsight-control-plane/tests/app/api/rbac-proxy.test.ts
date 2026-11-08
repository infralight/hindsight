import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/hindsight-client", () => ({
  DATAPLANE_URL: "http://dataplane",
  getDataplaneHeaders: (extra?: Record<string, string>) => ({ ...extra }),
}));

import { DELETE, GET, PUT } from "@/app/api/rbac/[...path]/route";

const params = (path: string[]) => ({ params: Promise.resolve({ path }) });

describe("rbac proxy", () => {
  let calls: Request[];
  let bodies: string[];

  beforeEach(() => {
    vi.stubEnv("HINDSIGHT_CP_AUTH_MODE", "rbac");
    calls = [];
    bodies = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const request = new Request(input, init);
        calls.push(request);
        const text = await request.text();
        bodies.push(text);
        if (request.method === "DELETE") return new Response(null, { status: 204 });
        return Response.json({ echoed: text ? JSON.parse(text) : null }, { status: 201 });
      })
    );
  });
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  it("forwards method, path, query and JSON body to /ext/rbac", async () => {
    const body = { principal_type: "team", principal_id: "t1", role: "writer" };
    const response = await PUT(
      new NextRequest("http://cp/api/rbac/banks/b1/grants?x=1", {
        method: "PUT",
        body: JSON.stringify(body),
      }),
      params(["banks", "b1", "grants"])
    );

    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe("PUT");
    expect(calls[0].url).toBe("http://dataplane/ext/rbac/banks/b1/grants?x=1");
    expect(JSON.parse(bodies[0])).toEqual(body);
    expect(response.status).toBe(201);
    expect(await response.json()).toEqual({ echoed: body });
  });

  it("passes a 204 through with no body", async () => {
    const response = await DELETE(
      new NextRequest("http://cp/api/rbac/tokens/tk1", { method: "DELETE" }),
      params(["tokens", "tk1"])
    );
    expect(response.status).toBe(204);
    expect(await response.text()).toBe("");
  });

  it("refuses dot segments, which URL parsing would resolve out of /ext/rbac", async () => {
    for (const dots of ["..", "."]) {
      const response = await GET(
        new NextRequest("http://cp/api/rbac/x"),
        params([dots, "..", "v1", "default", "banks"])
      );
      expect(response.status).toBe(400);
    }
    expect(calls).toHaveLength(0);
  });

  it("encodes a slash inside a segment", async () => {
    await GET(new NextRequest("http://cp/api/rbac/x"), params(["banks", "a/b", "access"]));
    expect(new URL(calls[0].url).pathname).toBe("/ext/rbac/banks/a%2Fb/access");
  });

  it("answers 404 outside rbac mode", async () => {
    vi.stubEnv("HINDSIGHT_CP_AUTH_MODE", "");
    const response = await GET(new NextRequest("http://cp/api/rbac/me"), params(["me"]));
    expect(response.status).toBe(404);
    expect(calls).toHaveLength(0);
  });
});
