/**
 * fork(rbac): OIDC authorization-code flow (with PKCE) against the configured issuer.
 *
 * The control plane only obtains and refreshes ID tokens; it never trusts their
 * contents for access decisions — the dataplane verifies every token it is sent.
 */

import { base64UrlEncode } from "@/lib/auth/user-session";

export interface OidcConfig {
  issuer: string;
  clientId: string;
  clientSecret: string;
}

export interface OidcTokens {
  idToken: string;
  refresh?: string;
  /** The ID token's `exp` (epoch seconds). */
  exp: number;
}

interface Discovery {
  authorization_endpoint: string;
  token_endpoint: string;
}

const discoveryCache = new Map<string, Discovery>();

export function oidcConfig(): OidcConfig | null {
  const issuer = process.env.HINDSIGHT_CP_OIDC_ISSUER?.replace(/\/+$/, "");
  const clientId = process.env.HINDSIGHT_CP_OIDC_CLIENT_ID;
  const clientSecret = process.env.HINDSIGHT_CP_OIDC_CLIENT_SECRET;
  return issuer && clientId && clientSecret ? { issuer, clientId, clientSecret } : null;
}

export async function discover(issuer: string): Promise<Discovery> {
  const cached = discoveryCache.get(issuer);
  if (cached) return cached;
  const res = await fetch(`${issuer}/.well-known/openid-configuration`);
  if (!res.ok) throw new Error(`OIDC discovery failed: ${res.status}`);
  const doc = (await res.json()) as Discovery;
  discoveryCache.set(issuer, doc);
  return doc;
}

/** The `exp` claim of a JWT, read without verifying it (the dataplane verifies). */
export function jwtExp(token: string): number {
  try {
    const payload = token.split(".")[1] ?? "";
    const json = atob(payload.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((payload.length + 3) % 4));
    const exp = Number(JSON.parse(json).exp);
    return Number.isFinite(exp) ? exp : 0;
  } catch {
    return 0;
  }
}

export async function pkcePair(): Promise<{ verifier: string; challenge: string }> {
  const verifier = base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)));
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return { verifier, challenge: base64UrlEncode(new Uint8Array(digest)) };
}

export function randomState(): string {
  return base64UrlEncode(crypto.getRandomValues(new Uint8Array(16)));
}

async function tokenRequest(cfg: OidcConfig, params: Record<string, string>): Promise<OidcTokens> {
  const { token_endpoint } = await discover(cfg.issuer);
  const res = await fetch(token_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ client_id: cfg.clientId, client_secret: cfg.clientSecret, ...params }),
  });
  if (!res.ok) throw new Error(`OIDC token request failed: ${res.status}`);
  const body = (await res.json()) as { id_token?: string; refresh_token?: string };
  if (!body.id_token) throw new Error("OIDC token response carried no id_token");
  return { idToken: body.id_token, refresh: body.refresh_token, exp: jwtExp(body.id_token) };
}

export function exchangeCode(cfg: OidcConfig, code: string, verifier: string, redirectUri: string) {
  return tokenRequest(cfg, {
    grant_type: "authorization_code",
    code,
    code_verifier: verifier,
    redirect_uri: redirectUri,
  });
}

export function refreshIdToken(cfg: OidcConfig, refreshToken: string) {
  return tokenRequest(cfg, { grant_type: "refresh_token", refresh_token: refreshToken });
}
