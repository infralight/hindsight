import { NextRequest, NextResponse } from "next/server";

import { setUserSession, tokenLoginEnabled, whoIs } from "@/lib/auth/rbac-login";
import { USER_SESSION_MAX_AGE_SECONDS, isRbacAuthMode, sessionSecret } from "@/lib/auth/user-session";

/** fork(rbac): sign in with a personal API token (checked by the dataplane). */
export async function POST(request: NextRequest) {
  const secret = sessionSecret();
  if (!isRbacAuthMode() || !tokenLoginEnabled() || !secret) {
    return NextResponse.json({ error: "Token sign-in is not enabled" }, { status: 404 });
  }
  let token = "";
  try {
    token = String(((await request.json()) as { token?: unknown }).token ?? "").trim();
  } catch {
    return NextResponse.json({ error: "Invalid request body" }, { status: 400 });
  }
  if (!token) return NextResponse.json({ error: "Token is required" }, { status: 400 });

  let user;
  try {
    user = await whoIs(token);
  } catch {
    return NextResponse.json({ error: "Could not reach the Hindsight API" }, { status: 502 });
  }
  if (!user) return NextResponse.json({ error: "Invalid, expired or revoked token" }, { status: 401 });

  const now = Math.floor(Date.now() / 1000);
  const exp = now + USER_SESSION_MAX_AGE_SECONDS;
  return setUserSession(
    NextResponse.json({ user }),
    request,
    { v: 1, kind: "token", cred: token, credExp: exp, exp, user },
    secret
  );
}
