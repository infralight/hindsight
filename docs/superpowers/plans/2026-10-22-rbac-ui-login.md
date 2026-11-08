# RBAC + SSO (control plane login) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Per-user login in the control plane: a login page (Google SSO and API-token sign-in), a logout button, and every dataplane call made as the signed-in user.

**Architecture:**
- **Session.** An encrypted, httpOnly session cookie holds the user's credential: an OIDC ID token plus refresh token, or an `hsp_` API token. It also holds the profile returned by `/ext/rbac/me`.
- **Middleware.** It requires the session in RBAC mode and refreshes expired ID tokens.
- **Request injection.** A `fetch` wrapper installed at startup puts the signed-in user's credential on every request to the dataplane. This covers the ~70 route handlers without editing them.

**Tech Stack:** Next.js 16 middleware/route handlers, Web Crypto (AES-GCM, SHA-256, PKCE), vitest.

**Spec:** `docs/superpowers/specs/2026-10-22-rbac-sso-design.md` ("Web UI (control plane)", "Authentication"). API side: `docs/superpowers/plans/2026-10-22-rbac-api.md`.

**Out of scope here (next UI plan):** My-tokens, bank-sharing and admin screens.

## Global Constraints

- RBAC mode is on when `HINDSIGHT_CP_AUTH_MODE=rbac`. In that mode:
  - `HINDSIGHT_CP_SESSION_SECRET` (≥ 32 chars) is required; startup logs an error and every page redirects to `/login` with a config error if it is missing.
  - `HINDSIGHT_CP_DATAPLANE_API_KEY` is never sent.
- OIDC env:
  - `HINDSIGHT_CP_OIDC_ISSUER`
  - `HINDSIGHT_CP_OIDC_CLIENT_ID`
  - `HINDSIGHT_CP_OIDC_CLIENT_SECRET`
  
  Google is enabled on the login page only when all three are set. The redirect URI is `<origin><basePath>/api/auth/oidc/callback`.
- API-token sign-in is shown unless `HINDSIGHT_CP_TOKEN_LOGIN=false`.
- Session cookie:
  - name `hindsight_cp_user`, httpOnly, sameSite `lax`, secure per `isSecureRequest`;
  - value is AES-GCM over JSON `{v:1, kind:"oidc"|"token", cred, refresh?, credExp, exp, user:{id,name,email,kind,is_admin}}`;
  - key is SHA-256(`HINDSIGHT_CP_SESSION_SECRET`);
  - session lifetime is 12 h (`exp`). `credExp` is the ID token's `exp` (token sessions use `exp`).
- The existing access-key mode keeps working unchanged when `HINDSIGHT_CP_AUTH_MODE` is unset.
- Every new user-facing string is added under `login.*` / `nav.*` in **all** locale files (English text where no translation exists); the catalog-parity test enforces this.
- Mark each edit to an upstream file with a `fork(rbac)` comment.

## Review Focus

1. **Expired ID token with no refresh token:** redirect to `/login`, never a dataplane 401 loop.
2. **Open redirect:** `returnTo` passes through `sanitizeReturnTo` on every path, OIDC state included.
3. **CSRF on OIDC callback:** `state` must match the short-lived state cookie, and the PKCE verifier must come from that cookie.
4. **Shared key leak:** in RBAC mode a request with no session must reach the dataplane with no `Authorization` header at all.
5. **Tampered cookie:** a bit flip yields "no session", never a crash.

---

### Task 1: Session crypto

**Files:** Create `src/lib/auth/user-session.ts`; Test `tests/lib/auth/user-session.test.ts`.

**Produces:**
- `type SessionUser = {id: string; name: string; email: string | null; kind: string; is_admin: boolean}`
- `type UserSession = {v: 1; kind: "oidc" | "token"; cred: string; refresh?: string; credExp: number; exp: number; user: SessionUser}`
- `USER_SESSION_COOKIE = "hindsight_cp_user"`, `USER_SESSION_MAX_AGE_SECONDS = 43200`
- `isRbacAuthMode(): boolean`
- `sealSession(s: UserSession, secret: string): Promise<string>` (base64url(iv ‖ ciphertext))
- `openSession(value: string | undefined, secret: string): Promise<UserSession | null>`, which returns `null` on any decode/auth failure, a wrong version, or `exp` in the past

- [ ] Tests: roundtrip; tampered byte → null; wrong secret → null; expired → null; garbage → null.
- [ ] Implement with `crypto.subtle` (AES-GCM, 12-byte IV). Run `npm test -- tests/lib/auth/user-session.test.ts`. Commit.

### Task 2: Middleware

**Files:** Modify `src/middleware.ts`; Create `src/lib/auth/oidc.ts` (`discover(issuer)`, `refreshIdToken(refresh): Promise<{idToken, refresh?, exp}>`); Test `tests/middleware-rbac.test.ts`.

In RBAC mode the middleware:
- uses the same public patterns as today;
- answers a missing or invalid session with `/login?returnTo=` for pages and a 401 plus `SESSION_REQUIRED_HEADER` for the API;
- redirects a signed-in visit to `/login` to `returnTo`;
- when `kind=="oidc"` and `credExp - 60 < now`, refreshes with the refresh token and sets a new cookie on the response, and treats a failed refresh or a missing refresh token as no session.

- [ ] Tests (mock `fetch` for the token endpoint):
  - page redirect;
  - API 401 header;
  - signed-in `/login` redirect;
  - expiry with refresh → the response sets a new cookie;
  - expiry without refresh → redirect;
  - access-key mode tests untouched and green.
- [ ] Implement. Run tests. Commit.

### Task 3: Per-user dataplane credential

**Files:**
- Create `src/lib/auth/dataplane-auth.ts`, exporting `installDataplaneAuth(dataplaneUrl: string, getSession: () => Promise<UserSession | null>)`, which wraps `globalThis.fetch` once.
- Modify `src/instrumentation.ts`: in RBAC mode, call it with a `getSession` that reads `cookies()` and returns `null` outside a request.
- Modify `src/lib/hindsight-client.ts`: skip the static key in RBAC mode.
- Test `tests/lib/auth/dataplane-auth.test.ts`.

For URLs under the dataplane URL, the wrapper:
- deletes any `Authorization` header;
- sets `Bearer <session.cred>` when a session exists.

Other URLs pass through untouched.

- [ ] Tests:
  - dataplane request with a session → the user's bearer;
  - without a session → no Authorization even if the caller set one;
  - non-dataplane URL untouched;
  - a `Request` object input works.
- [ ] Implement. Run. Commit.

### Task 4: Auth routes

**Files:**
- Create `src/app/api/auth/token-login/route.ts`: POST `{token}` → GET `<dataplane>/ext/rbac/me` with the token → 200 sets the session (`kind:"token"`); a dataplane 401 → 401 `invalidToken`.
- Create `src/app/api/auth/oidc/start/route.ts`: GET `?returnTo=` → 302 to the issuer's `authorization_endpoint`. Parameters: `response_type=code`, `scope=openid email profile`, `access_type=offline`, `prompt=consent`, `state`, `code_challenge` (S256), `redirect_uri`. It sets the `hindsight_cp_oidc` cookie (sealed `{state, verifier, returnTo}`, 10 min).
- Create `src/app/api/auth/oidc/callback/route.ts`. It checks `state` against the cookie and exchanges the code (with the verifier and client secret). It calls `/ext/rbac/me` with the `id_token`, sets the session (`kind:"oidc"`, `credExp` from the token's `exp`), clears the state cookie, and redirects to `returnTo`. On any failure it redirects to `/login?error=sso`.
- Create `src/app/api/auth/me/route.ts`: GET → `{user, auth: {mode:"rbac", google: boolean, tokenLogin: boolean}}`, or 401.
- Modify `src/app/api/auth/logout/route.ts`: also clear `hindsight_cp_user`.
- Modify `src/app/api/version/route.ts`: `features.access_key_auth` is also true in RBAC mode, so the existing logout button shows.
- Tests: `tests/app/api/auth/*.test.ts`. Each route covers its happy path and each failure branch above (mocked `fetch`).

- [ ] Write the tests, implement, run, commit.

### Task 5: Login page, user menu

**Files:**
- Modify `src/app/[locale]/login/page.tsx`. In RBAC mode (from `/api/auth/me` `auth` config, fetched without a session via a public `GET /api/auth/config`), show:
  - a "Sign in with Google" button → `/api/auth/oidc/start?returnTo=`;
  - an "or sign in with an API token" form → `/api/auth/token-login`;
  - `?error=sso` → an error line.
  
  Otherwise the page shows today's access-key form.
- Create `src/app/api/auth/config/route.ts` (public: `{mode, google, tokenLogin}`).
- Modify `src/components/bank-selector.tsx`: show the signed-in user's name (from `/api/auth/me`) next to the logout button.
- Add `login.*` / `nav.*` keys to all locales.

- [ ] Tests: the config route; the messages parity suite is green. Build: `npm run build` succeeds. Commit.
- [ ] Run locally against the demo API (`HINDSIGHT_CP_AUTH_MODE=rbac`) and sign in with a demo token: the user name and logout show, and the bank list is per-user.
