/**
 * fork(rbac): shared pieces of the per-user login routes.
 */

import { NextRequest, NextResponse } from "next/server";

import { rawFetch } from "@/lib/auth/dataplane-auth";
import { sessionCookieOptions } from "@/lib/auth/session";
import {
  USER_SESSION_COOKIE,
  USER_SESSION_MAX_AGE_SECONDS,
  sealSession,
  type SessionUser,
  type UserSession,
} from "@/lib/auth/user-session";
import { withBasePath } from "@/lib/base-path";
import { DATAPLANE_URL } from "@/lib/hindsight-client";

export const OIDC_STATE_COOKIE = "hindsight_cp_oidc";
export const OIDC_STATE_MAX_AGE_SECONDS = 600;

export interface OidcState {
  state: string;
  verifier: string;
  returnTo: string;
  exp: number;
}

export function tokenLoginEnabled(): boolean {
  return process.env.HINDSIGHT_CP_TOKEN_LOGIN !== "false";
}

/**
 * Who the dataplane says this credential belongs to: the user, null when it is
 * refused (401/403), or throws when the dataplane cannot answer.
 */
export async function whoIs(credential: string): Promise<SessionUser | null> {
  const res = await rawFetch()(`${DATAPLANE_URL}/ext/rbac/me`, {
    headers: { Authorization: `Bearer ${credential}` },
  });
  if (res.status === 401 || res.status === 403) return null;
  if (!res.ok) throw new Error(`dataplane /ext/rbac/me answered ${res.status}`);
  return (await res.json()) as SessionUser;
}

/** The origin the browser used (a proxy's forwarded host/proto win), or HINDSIGHT_CP_PUBLIC_URL. */
export function publicOrigin(request: NextRequest): string {
  const configured = process.env.HINDSIGHT_CP_PUBLIC_URL?.replace(/\/+$/, "");
  if (configured) return configured;
  const host =
    request.headers.get("x-forwarded-host") ?? request.headers.get("host") ?? request.nextUrl.host;
  const proto =
    request.headers.get("x-forwarded-proto")?.split(",")[0]?.trim() ??
    request.nextUrl.protocol.replace(":", "");
  return `${proto}://${host}`;
}

export function oidcRedirectUri(request: NextRequest): string {
  return `${publicOrigin(request)}${withBasePath("/api/auth/oidc/callback")}`;
}

export async function setUserSession(
  response: NextResponse,
  request: NextRequest,
  session: UserSession,
  secret: string
): Promise<NextResponse> {
  response.cookies.set({
    name: USER_SESSION_COOKIE,
    value: await sealSession(session, secret),
    ...sessionCookieOptions(request),
    maxAge: USER_SESSION_MAX_AGE_SECONDS,
  });
  return response;
}
