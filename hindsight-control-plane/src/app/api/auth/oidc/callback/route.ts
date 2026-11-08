import { NextRequest, NextResponse } from "next/server";

import { exchangeCode, oidcConfig } from "@/lib/auth/oidc";
import {
  OIDC_STATE_COOKIE,
  type OidcState,
  oidcRedirectUri,
  publicOrigin,
  setUserSession,
  whoIs,
} from "@/lib/auth/rbac-login";
import { sessionCookieOptions } from "@/lib/auth/session";
import {
  USER_SESSION_MAX_AGE_SECONDS,
  isRbacAuthMode,
  openValue,
  sessionSecret,
} from "@/lib/auth/user-session";
import { withBasePath } from "@/lib/base-path";

/** fork(rbac): finish SSO — check state, exchange the code, ask the dataplane who this is. */
export async function GET(request: NextRequest) {
  const origin = publicOrigin(request);
  const failed = () => {
    const response = NextResponse.redirect(new URL(withBasePath("/login?error=sso"), origin));
    response.cookies.set({
      name: OIDC_STATE_COOKIE,
      value: "",
      ...sessionCookieOptions(request),
      maxAge: 0,
    });
    return response;
  };

  const cfg = oidcConfig();
  const secret = sessionSecret();
  if (!isRbacAuthMode() || !cfg || !secret) return failed();

  const flow = await openValue<OidcState>(request.cookies.get(OIDC_STATE_COOKIE)?.value, secret);
  const params = request.nextUrl.searchParams;
  const code = params.get("code");
  const now = Math.floor(Date.now() / 1000);
  if (!flow || !code || flow.exp < now || params.get("state") !== flow.state) return failed();

  try {
    const tokens = await exchangeCode(cfg, code, flow.verifier, oidcRedirectUri(request));
    const user = await whoIs(tokens.idToken);
    if (!user) return failed();
    const response = NextResponse.redirect(new URL(withBasePath(flow.returnTo), origin));
    response.cookies.set({
      name: OIDC_STATE_COOKIE,
      value: "",
      ...sessionCookieOptions(request),
      maxAge: 0,
    });
    return setUserSession(
      response,
      request,
      {
        v: 1,
        kind: "oidc",
        cred: tokens.idToken,
        refresh: tokens.refresh,
        credExp: tokens.exp,
        exp: now + USER_SESSION_MAX_AGE_SECONDS,
        user,
      },
      secret
    );
  } catch {
    return failed();
  }
}
