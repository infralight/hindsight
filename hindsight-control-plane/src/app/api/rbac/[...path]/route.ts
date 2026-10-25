/**
 * fork(rbac): forwards /api/rbac/* to the dataplane's /ext/rbac/* (sharing, tokens,
 * users and teams). The per-user fetch wrapper adds the signed-in user's credential,
 * so the dataplane decides what this caller may see or change.
 */

import { NextRequest, NextResponse } from "next/server";
import { DATAPLANE_URL, getDataplaneHeaders } from "@/lib/hindsight-client";

type Context = { params: Promise<{ path: string[] }> };

async function forward(request: NextRequest, { params }: Context): Promise<Response> {
  if (process.env.HINDSIGHT_CP_AUTH_MODE !== "rbac") {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }
  const { path } = await params;
  // encodeURIComponent leaves `.` and `..` as they are, and URL parsing would resolve
  // them out of /ext/rbac.
  if (path.some((segment) => segment === "." || segment === "..")) {
    return NextResponse.json({ error: "Invalid path" }, { status: 400 });
  }
  const url = new URL(
    `${DATAPLANE_URL}/ext/rbac/${path.map(encodeURIComponent).join("/")}${request.nextUrl.search}`
  );
  const hasBody = request.method !== "GET" && request.method !== "DELETE";
  const response = await fetch(url, {
    method: request.method,
    headers: getDataplaneHeaders({ "Content-Type": "application/json" }),
    body: hasBody ? await request.text() : undefined,
    cache: "no-store",
  });
  const body = response.status === 204 ? null : await response.text();
  return new Response(body, {
    status: response.status,
    headers: body ? { "Content-Type": "application/json" } : undefined,
  });
}

export { forward as GET, forward as POST, forward as PUT, forward as PATCH, forward as DELETE };
