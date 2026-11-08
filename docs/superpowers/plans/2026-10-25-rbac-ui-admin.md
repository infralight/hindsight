# RBAC control-plane screens Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let people manage RBAC from the control plane: share a bank (visibility, owner, grants), manage their own API tokens, and — for admins — manage users, service accounts and teams.

**Architecture:** One catch-all control-plane route proxies `/api/rbac/*` to the dataplane's `/ext/rbac/*` (the per-user fetch wrapper already attaches the signed-in user's credential). A typed client (`src/lib/rbac-api.ts`) sits on the existing `ControlPlaneClient.fetchApi`, so errors toast and a lost session redirects to login exactly as elsewhere. Screens: an **Access** sub-tab in the bank's configuration view, a **My tokens** page, and an **Admin** page with *Users & service accounts* and *Teams* tabs, reached from a menu on the signed-in user in the header. `GET /ext/rbac/banks/{id}/access` returns `my_capabilities`, which drives what each screen enables.

**Tech Stack:** Next.js 16 (App Router), React 19, Tailwind v4, the repo's shadcn components (`components/ui/*`), next-intl, vitest + @testing-library/react.

**Spec:** `docs/superpowers/specs/2026-10-22-rbac-sso-design.md` (section "Web UI (control plane)"; roles and rules under "Banks: visibility, roles and capabilities").

## Global Constraints

- Follow the existing control plane look. No redesign. Reuse `components/ui/*` (Button, Input, Select, Table, Dialog, AlertDialog, Popover, Command, UnderlineTabs, Switch).
- Hide or disable actions the user may not perform; the API remains the enforcement point.
- Only Owner or Admin change visibility, owner and grants; roles are `reader` | `writer` | `owner`.
- A public bank is deleted only by an Admin; a private bank by its Owner or an Admin.
- Every new screen and the proxy exist only when `HINDSIGHT_CP_AUTH_MODE=rbac`; access-key mode is unchanged.
- Fork patches to upstream files carry a `fork(rbac)` comment; new files say so in their header.
- New strings go in all 10 `src/messages/*.json` locales (English text, as the login slice did); `tests/messages` must stay green.
- No edits under `.github/workflows`.

## Review Focus

1. **Losing `manage` mid-session** (owner transfers ownership or removes their own grant): the Access view must re-render from the `BankAccess` the mutation returns and drop to read-only, with no stale enabled controls. → test in Task 2.
2. **A non-admin opening `/admin` directly**: one clear "admins only" panel, not a cascade of 403 toasts. → test in Task 4.
3. **A new token is shown exactly once**: closing the dialog discards it from state; it never reaches the URL, logs or a toast. → test in Task 3.
4. **Directory search** with no matches, or typing fast: debounced, shows an empty state, never offers a principal already granted. → test in Task 2.
5. **Access-key mode**: no Access tab, no user menu items, `/api/rbac/*` answers 404. → tests in Tasks 1 and 5.

---

### Task 1: RBAC proxy, client and feature flag

**Files:**
- Create: `hindsight-control-plane/src/app/api/rbac/[...path]/route.ts`
- Create: `hindsight-control-plane/src/lib/rbac-api.ts`
- Modify: `hindsight-control-plane/src/lib/api.ts` (`fetchApi`: drop `private`, `fork(rbac)` comment)
- Modify: `hindsight-control-plane/src/app/api/version/route.ts`, `src/lib/features-context.tsx` (add `rbac: boolean`)
- Test: `hindsight-control-plane/tests/app/api/rbac-proxy.test.ts`, `tests/lib/rbac-api.test.ts`

**Interfaces:**
- Produces: route handlers `GET|POST|PUT|PATCH|DELETE(request, { params: Promise<{ path: string[] }> })`.
- Produces (`rbac-api.ts`), types mirroring `hindsight_ext_rbac/http.py`:
  `Role = "reader" | "writer" | "owner"`, `Capability = "read" | "write" | "manage" | "delete_bank"`,
  `Principal {id, kind, email: string | null, name, is_admin}`, `PrincipalAdmin extends Principal {disabled, is_bootstrap_admin, created_at, last_seen_at: string | null}`,
  `Token {id, name, prefix, created_at, expires_at, last_used_at, revoked}`, `NewToken {id, name, prefix, token, expires_at}`,
  `Team {id, name}`, `TeamWithMembers extends Team {members: Principal[]}`, `Directory {principals: Principal[], teams: Team[]}`,
  `Grant {principal_type: "principal" | "team", principal_id, name, role: Role}`,
  `BankAccess {bank_id, visibility: "private" | "public", owner: Principal | null, grants: Grant[], my_role: Role | null, my_capabilities: Capability[]}`.
- Produces `export const rbac = { me, directory(q), listTokens, createToken(name, expiresAt?), revokeToken(id), listPrincipals, updatePrincipal(id, {is_admin?, disabled?}), createServiceAccount(name), listPrincipalTokens(id), createPrincipalToken(id, name, expiresAt?), listTeams, createTeam(name), renameTeam(id, name), deleteTeam(id), addMember(teamId, principalId), removeMember(teamId, principalId), getAccess(bankId), updateAccess(bankId, {visibility?, owner_id?}), putGrant(bankId, {principal_type, principal_id, role}), deleteGrant(bankId, type, id) }`, every method returning the dataplane body (`Promise<void>` for 204s).

- [ ] **Step 1: Write the failing tests**
  - `forwards method, path, query and JSON body to /ext/rbac` — `PUT /api/rbac/banks/b1/grants?x=1` with a body reaches `${DATAPLANE}/ext/rbac/banks/b1/grants?x=1` with the same method and body; status and JSON body come back unchanged.
  - `passes a 204 through with no body`.
  - `encodes each path segment so it cannot leave /ext/rbac` — path `["..", "..", "v1", "default", "banks"]` is requested as `/ext/rbac/..%2F..`-style encoded segments (assert the outgoing URL's pathname starts with `/ext/rbac/` and contains no `/v1/`).
  - `answers 404 outside rbac mode` (no dataplane call made).
  - `rbac.putGrant sends the grant to /api/rbac/banks/{id}/grants` and `rbac.deleteGrant uses /grants/{type}/{id}` (assert URL and method via a `fetch` spy, as `tests/lib/api.test.ts` does).
- [ ] **Step 2: Run** `npx vitest run tests/app/api/rbac-proxy.test.ts tests/lib/rbac-api.test.ts` — Expected: FAIL (modules missing).
- [ ] **Step 3: Implement.** Route: build `new URL(DATAPLANE_URL)` + `/ext/rbac/` + `path.map(encodeURIComponent).join("/")` + original search; forward body for non-GET/DELETE; send `getDataplaneHeaders({"Content-Type": "application/json"})` (the wrapper replaces any credential). Return `new Response(body, { status })`, empty for 204. Feature flag: `features.rbac = process.env.HINDSIGHT_CP_AUTH_MODE === "rbac"`, default `false` in the context.
- [ ] **Step 4: Run** the same tests — Expected: PASS. Then `npx vitest run` — all green.
- [ ] **Step 5: Commit** `feat(control-plane): proxy and client for the RBAC API`.

### Task 2: Bank Access sub-tab

**Files:**
- Create: `hindsight-control-plane/src/components/rbac/bank-access-view.tsx`
- Create: `hindsight-control-plane/src/components/rbac/directory-picker.tsx`
- Modify: `hindsight-control-plane/src/app/[locale]/banks/[bankId]/page.tsx` (`BankConfigTab` gains `"access"`; tab listed when `features.rbac`; renders `<BankAccessView bankId>`)
- Modify: `src/messages/*.json` (`rbac.access.*`)
- Test: `hindsight-control-plane/tests/components/rbac/bank-access-view.test.tsx`, `tests/components/rbac/directory-picker.test.tsx`

**Interfaces:**
- Consumes: `rbac.getAccess/updateAccess/putGrant/deleteGrant/directory` and the types from Task 1.
- Produces: `BankAccessView({ bankId }: { bankId: string })`; `DirectoryPicker({ kinds, exclude, onPick, placeholder }: { kinds: ("principal" | "team")[]; exclude: Set<string>; onPick: (p: { type: "principal" | "team"; id: string; name: string }) => void; placeholder: string })` — Popover + Command, debounced (250 ms) `rbac.directory(q)` search. Task 4 reuses it.

Layout (existing card/table look): **Visibility** — Private / Public select with one line explaining each. **Owner** — name + email, "Transfer ownership" opens a principals-only picker. **People and teams with access** — table (name, kind, role select, remove) and an "Add people or teams" row (picker + role select defaulting to `reader` + Add). Read-only users see the same data with controls disabled and the note "Only the owner or an admin can change who has access."

- [ ] **Step 1: Write the failing tests** (mock `rbac`):
  - `shows visibility, owner and grants from getAccess`.
  - `disables every control without the manage capability`.
  - `adding a team as writer calls putGrant with principal_type team and role writer`.
  - `changing a grant's role calls putGrant; removing calls deleteGrant`.
  - `switching to private calls updateAccess({visibility: "private"})`.
  - `drops to read-only when the mutation's BankAccess no longer has manage` (Review Focus 1).
  - Picker: `debounces the directory search`, `shows an empty state when nothing matches`, `does not offer principals already in exclude` (Review Focus 4).
- [ ] **Step 2: Run** `npx vitest run tests/components/rbac` — Expected: FAIL.
- [ ] **Step 3: Implement** both components; state is the latest `BankAccess` returned by any call (no separate refetch).
- [ ] **Step 4: Run** the tests — PASS; `npx vitest run` — green; `npx tsc --noEmit -p .` clean.
- [ ] **Step 5: Commit** `feat(control-plane): bank Access tab for visibility, owner and sharing`.

### Task 3: My tokens page

**Files:**
- Create: `hindsight-control-plane/src/app/[locale]/tokens/page.tsx`
- Create: `hindsight-control-plane/src/components/rbac/token-list.tsx` (shared with Task 4's service-account tokens)
- Modify: `src/messages/*.json` (`rbac.tokens.*`)
- Test: `hindsight-control-plane/tests/components/rbac/token-list.test.tsx`

**Interfaces:**
- Consumes: `rbac.listTokens/createToken/revokeToken`, or the principal-scoped trio for service accounts.
- Produces: `TokenList({ load, create, revoke }: { load: () => Promise<Token[]>; create: (name: string, expiresAt?: string) => Promise<NewToken>; revoke: (id: string) => Promise<void> })`.

Page: header (`BankSelector`) + title "My API tokens" + one line on what tokens are for (agents, MCP, scripts). Table: name, prefix (`hsp_xxxx…`), created, last used, expires, status. "New token" dialog: name + optional expiry date; on success the dialog shows the token once in a read-only field with a Copy button and "You won't see this again". Revoke asks for confirmation (AlertDialog).

- [ ] **Step 1: Write the failing tests:** `lists tokens with prefix and status`; `shows a new token once and forgets it when the dialog closes` (after close, token text is absent from the document; Review Focus 3); `revokes only after confirmation`.
- [ ] **Step 2: Run** `npx vitest run tests/components/rbac/token-list.test.tsx` — FAIL.
- [ ] **Step 3: Implement** `TokenList` and the page.
- [ ] **Step 4: Run** — PASS; full suite green.
- [ ] **Step 5: Commit** `feat(control-plane): My tokens page`.

### Task 4: Admin page — users, service accounts, teams

**Files:**
- Create: `hindsight-control-plane/src/app/[locale]/admin/page.tsx`
- Create: `hindsight-control-plane/src/components/rbac/admin-users.tsx`, `src/components/rbac/admin-teams.tsx`
- Modify: `src/messages/*.json` (`rbac.admin.*`)
- Test: `hindsight-control-plane/tests/components/rbac/admin-users.test.tsx`, `tests/components/rbac/admin-teams.test.tsx`, `tests/components/rbac/admin-page.test.tsx`

**Interfaces:**
- Consumes: `rbac.me`, principal/team methods from Task 1, `DirectoryPicker` (Task 2), `TokenList` (Task 3).
- Produces: `AdminUsers()`, `AdminTeams()`; page tab state in `?tab=users|teams` (URL as state).

Users tab: table — name, email, kind (user / service account), Admin badge, status, last seen. Row actions: Make admin / Remove admin (disabled with a tooltip for bootstrap admins and service accounts, matching the API's 409 rules), Disable / Enable. "New service account" (name). A service-account row expands to its `TokenList`. Teams tab: teams with member chips; New team; Rename; Delete (confirm); Add member (principals-only picker); Remove member.

- [ ] **Step 1: Write the failing tests:** `promote is disabled for bootstrap admins and service accounts`; `disabling a user calls updatePrincipal({disabled: true})`; `creating a service account adds its row and opens its tokens`; `adding a member calls addMember with the picked principal`; `deleting a team asks first`; `a non-admin sees an admins-only panel and no list calls are made` (Review Focus 2).
- [ ] **Step 2: Run** `npx vitest run tests/components/rbac/admin-*.test.tsx` — FAIL.
- [ ] **Step 3: Implement** the page and both tabs.
- [ ] **Step 4: Run** — PASS; full suite green.
- [ ] **Step 5: Commit** `feat(control-plane): admin page for users, service accounts and teams`.

### Task 5: Navigation and capability gating

**Files:**
- Modify: `hindsight-control-plane/src/components/signed-in-user.tsx` (becomes a DropdownMenu: name/email, My tokens, Admin when `is_admin`)
- Create: `hindsight-control-plane/src/lib/use-bank-access.ts`
- Modify: `hindsight-control-plane/src/app/[locale]/banks/[bankId]/page.tsx` (hide Webhooks and Audit-log sub-tabs without `manage`; a read-only banner when the caller lacks `write`)
- Modify: the delete-bank action (locate via `deleteBank(` callers) — hidden without `delete_bank`
- Test: `hindsight-control-plane/tests/components/rbac/signed-in-user.test.tsx`, `tests/lib/use-bank-access.test.tsx`

**Interfaces:**
- Produces: `useBankAccess(bankId: string | null): { access: BankAccess | null; can: (c: Capability) => boolean }` — fetches once per bank id; outside rbac mode `can` returns `true` (upstream behaviour) and nothing is fetched.

- [ ] **Step 1: Write the failing tests:** `the user menu links to My tokens, and to Admin only for admins`; `can() is true for everything outside rbac mode without fetching` (Review Focus 5); `can("delete_bank") is false for a writer on a public bank`.
- [ ] **Step 2: Run** — FAIL.
- [ ] **Step 3: Implement** the menu, hook and gating.
- [ ] **Step 4: Run** — PASS; full suite, `tsc`, `npm run lint` clean. Manual check on the demo: alice sees Access/Webhooks on her private bank; bob, as reader on it, sees the read-only banner and no delete; admin sees Admin in the menu.
- [ ] **Step 5: Commit** `feat(control-plane): user menu and capability-aware bank actions`.
