import { NextRequest, NextResponse } from "next/server";

import { USER_SESSION_COOKIE, openSession, sessionSecret } from "@/lib/auth/user-session";

/** fork(rbac): the signed-in user, as recorded when they signed in. */
export async function GET(request: NextRequest) {
  const secret = sessionSecret();
  const session = secret
    ? await openSession(request.cookies.get(USER_SESSION_COOKIE)?.value, secret)
    : null;
  if (!session) return NextResponse.json({ error: "Not signed in" }, { status: 401 });
  return NextResponse.json({ user: session.user, auth: session.kind });
}
