/**
 * fork(rbac): make every dataplane call as the signed-in user.
 *
 * ~70 route handlers reach the dataplane through `fetch` (directly, or via the
 * generated SDK), each with the static `getDataplaneHeaders()`. Rather than thread a
 * credential through all of them, this wraps `fetch` once at startup: a request to
 * the dataplane gets the current user's bearer — or none at all — whatever the
 * caller set. Other hosts are untouched.
 */

import type { UserSession } from "@/lib/auth/user-session";

// On globalThis, not module scope: instrumentation and route handlers are bundled
// separately, so a module-level variable would not be shared between them.
const UNWRAPPED = Symbol.for("hindsight.cp.unwrappedFetch");
type FetchHolder = { [UNWRAPPED]?: typeof fetch };

/** fetch without the per-user credential swap — for login, where the credential being
 * checked is the one the caller supplies, not the (absent) session's. */
export function rawFetch(): typeof fetch {
  return (globalThis as FetchHolder)[UNWRAPPED] ?? globalThis.fetch;
}

export function installDataplaneAuth(dataplaneUrl: string, getSession: () => Promise<UserSession | null>): void {
  const base = new URL(dataplaneUrl);
  const prefix = base.pathname.replace(/\/+$/, "");
  const holder = globalThis as FetchHolder;
  if (holder[UNWRAPPED]) return; // already installed
  const inner = globalThis.fetch;
  holder[UNWRAPPED] = inner;

  const isDataplane = (url: URL) =>
    url.origin === base.origin && (prefix === "" || url.pathname === prefix || url.pathname.startsWith(`${prefix}/`));

  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = new Request(input, init);
    if (!isDataplane(new URL(request.url))) return inner(input, init);
    const headers = new Headers(request.headers);
    headers.delete("authorization");
    const session = await getSession();
    if (session) headers.set("authorization", `Bearer ${session.cred}`);
    return inner(new Request(request, { headers }));
  }) as typeof fetch;
}
