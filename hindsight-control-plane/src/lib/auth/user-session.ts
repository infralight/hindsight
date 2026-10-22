/**
 * fork(rbac): per-user sessions for the control plane.
 *
 * The session cookie carries the signed-in user's own credential — an OIDC ID token
 * (plus refresh token) or a personal `hsp_` API token — sealed with AES-GCM so the
 * browser can neither read nor forge it. Every dataplane call is made with that
 * credential (see dataplane-auth.ts); the dataplane decides what the user may do.
 */

export const USER_SESSION_COOKIE = "hindsight_cp_user";
export const USER_SESSION_MAX_AGE_SECONDS = 60 * 60 * 12;
const SESSION_VERSION = 1;
const IV_BYTES = 12;

export interface SessionUser {
  id: string;
  name: string;
  email: string | null;
  kind: string;
  is_admin: boolean;
}

export interface UserSession {
  v: 1;
  kind: "oidc" | "token";
  /** The bearer sent to the dataplane. */
  cred: string;
  /** OIDC refresh token, when the issuer granted one. */
  refresh?: string;
  /** When `cred` stops being accepted (epoch seconds). */
  credExp: number;
  /** When the session itself ends (epoch seconds). */
  exp: number;
  user: SessionUser;
}

export function isRbacAuthMode(): boolean {
  return process.env.HINDSIGHT_CP_AUTH_MODE === "rbac";
}

export function sessionSecret(): string | null {
  const secret = process.env.HINDSIGHT_CP_SESSION_SECRET ?? "";
  return secret.length >= 32 ? secret : null;
}

export function sealSession(session: UserSession, secret: string): Promise<string> {
  return sealValue(session, secret);
}

export async function openSession(
  value: string | undefined,
  secret: string
): Promise<UserSession | null> {
  const session = await openValue<UserSession>(value, secret);
  if (!session || session.v !== SESSION_VERSION || typeof session.cred !== "string") return null;
  if (session.exp <= Math.floor(Date.now() / 1000)) return null;
  return session;
}

/** AES-GCM-seal any JSON value under the session secret. */
export async function sealValue(value: unknown, secret: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const plaintext = new TextEncoder().encode(JSON.stringify(value));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    await aesKey(secret),
    plaintext
  );
  const sealed = new Uint8Array(IV_BYTES + ciphertext.byteLength);
  sealed.set(iv);
  sealed.set(new Uint8Array(ciphertext), IV_BYTES);
  return base64UrlEncode(sealed);
}

/** The value sealed by `sealValue`, or null for anything tampered, foreign or malformed. */
export async function openValue<T>(value: string | undefined, secret: string): Promise<T | null> {
  if (!value) return null;
  try {
    const sealed = base64UrlDecode(value);
    if (sealed.length <= IV_BYTES) return null;
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: sealed.slice(0, IV_BYTES) },
      await aesKey(secret),
      sealed.slice(IV_BYTES)
    );
    return JSON.parse(new TextDecoder().decode(plaintext)) as T;
  } catch {
    return null;
  }
}

async function aesKey(secret: string): Promise<CryptoKey> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secret));
  return crypto.subtle.importKey("raw", digest, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

export function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function base64UrlDecode(value: string): Uint8Array {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(base64 + "=".repeat((4 - (base64.length % 4)) % 4));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}
