import { NextResponse } from "next/server";

import { oidcConfig } from "@/lib/auth/oidc";
import { tokenLoginEnabled } from "@/lib/auth/rbac-login";
import { isRbacAuthMode } from "@/lib/auth/user-session";

/** fork(rbac): which sign-in options the login page offers (public). */
export async function GET() {
  if (!isRbacAuthMode()) {
    return NextResponse.json({ mode: process.env.HINDSIGHT_CP_ACCESS_KEY ? "access_key" : "none" });
  }
  return NextResponse.json({
    mode: "rbac",
    google: oidcConfig() !== null,
    tokenLogin: tokenLoginEnabled(),
  });
}
