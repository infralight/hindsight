import { NextRequest, NextResponse } from "next/server";

import { discover, oidcConfig, pkcePair, randomState } from "@/lib/auth/oidc";
import {
  OIDC_STATE_COOKIE,
  OIDC_STATE_MAX_AGE_SECONDS,
  type OidcState,
  oidcRedirectUri,
} from "@/lib/auth/rbac-login";
import { sessionCookieOptions } from "@/lib/auth/session";
import { isRbacAuthMode, sealValue, sessionSecret } from "@/lib/auth/user-session";
import { sanitizeReturnTo, withBasePath } from "@/lib/base-path";

/** fork(rbac): send the browser to the identity provider (authorization code + PKCE). */
export async function GET(request: NextRequest) {
  const cfg = oidcConfig();
  const secret = sessionSecret();
  if (!isRbacAuthMode() || !cfg || !secret) {
    return NextResponse.json({ error: "SSO is not configured" }, { status: 404 });
  }
  try {
    const { authorization_endpoint } = await discover(cfg.issuer);
    const { verifier, challenge } = await pkcePair();
    const state = randomState();
    const target = new URL(authorization_endpoint);
    target.search = new URLSearchParams({
      response_type: "code",
      client_id: cfg.clientId,
      redirect_uri: oidcRedirectUri(request),
      scope: "openid email profile",
      state,
      code_challenge: challenge,
      code_challenge_method: "S256",
      access_type: "offline",
      prompt: "consent",
    }).toString();

    const flow: OidcState = {
      state,
      verifier,
      returnTo: sanitizeReturnTo(request.nextUrl.searchParams.get("returnTo")),
      exp: Math.floor(Date.now() / 1000) + OIDC_STATE_MAX_AGE_SECONDS,
    };
    const response = NextResponse.redirect(target);
    response.cookies.set({
      name: OIDC_STATE_COOKIE,
      value: await sealValue(flow, secret),
      ...sessionCookieOptions(request),
      maxAge: OIDC_STATE_MAX_AGE_SECONDS,
    });
    return response;
  } catch {
    return NextResponse.redirect(new URL(withBasePath("/login?error=sso"), request.url));
  }
}
