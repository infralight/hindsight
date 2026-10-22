# Hindsight fork: SSO login and bank-level RBAC

Status: approved · Date: 2026-10-22

## Why

Our shared Hindsight deployment has **no authentication at all**: anyone who can reach it
on the network can read, write or delete any memory bank through the UI, the REST API or MCP.
Engineers' coding agents (the coding-agents plugin, MCP, the CLI) and at least one bot write
to it continuously.

We want people to log in with their company Google account and to control who can see and
change each bank. Upstream offers SSO and RBAC only in its commercial cloud and enterprise
tiers, so this will not be accepted upstream; we maintain it in this fork.

## Goals

1. Every human, agent and bot request is attributed to a principal.
2. Web UI login through company SSO (Google Workspace via OIDC; any OIDC issuer by config).
3. Every bank is **private** or **public** and can be shared with principals or teams at a role.
4. Agents keep working: they authenticate with personal API tokens that act as their owner.
   Bots use service accounts.
5. Existing banks and every existing agent setup keep working through the switch-over.
6. Admins manage users, service accounts, teams and any bank.
7. The audit log records who did what, for every bank, and owners cannot switch it off.

## Non-goals (v1)

- Syncing teams from Google Groups, SCIM, or any IdP group sync. Teams are managed in Hindsight.
- A team-admin role (only global admins manage teams).
- SAML, or MFA beyond what the IdP enforces.
- Access control finer than a bank (per-memory, per-tag, per-document). Upstream tag scoping is
  left untouched and unused.
- Schema-per-user isolation. All banks stay in the existing `public` schema.
- Oracle support for the RBAC tables (PostgreSQL only).
- Contributing RBAC/SSO upstream. (Small generic core fixes may be upstreamed to shrink the fork.)
- Changes to client SDKs or agent integrations: they already send `Authorization: Bearer <token>`.

## Anti-goals (failure even if it "works")

- Existing memories disappear, move, or become inaccessible at cutover to people who use them today.
- Every engineer's agent breaks at the same moment with no warning or grace period.
- Any path reaches bank data without the permission check: HTTP routes, MCP tools, background
  worker jobs, `/ext/*` endpoints, and routes without a bank in the path
  (`/v1/default/chunks/...`, `/v1/default/files/download/...`).
- The API trusts an identity header or claim an arbitrary caller on the network can forge.
- The fork diverges so far from upstream that merging upstream releases stops being routine.

## Principals

- **User**: identified by verified email from the OIDC ID token. Only emails in the allowed
  domain(s) may log in. A user record is created on first login.
- **Service account**: a non-login principal for bots, created by an admin, authenticates only
  with API tokens minted by an admin. A service account can never be admin.
- **Anonymous**: only exists while auth mode is `optional` (see Migration).

**Admins** are Owner on every bank and manage principals and teams. Admins are bootstrapped
from a configured email list; config-listed admins cannot be demoted or disabled in the UI.
Admins can promote or demote other users.

**Teams**: only admins create, rename and delete teams and manage membership. A principal can
be in any number of teams.

**Disabling** a principal (admin action) blocks login and invalidates all of its API tokens
immediately. Removing someone from Google Workspace blocks new logins but does not revoke tokens,
so offboarding means disabling the principal in Hindsight too.

## Banks: visibility, roles and capabilities

Every bank has a **visibility** (`private` | `public`), zero or one **owner** principal, and a
list of **grants** (principal or team → role).

Capabilities:
- **read**: recall, reflect, every list/get/search/stats/graph/export/clone-source read.
- **write**: retain (incl. files), memory updates/invalidation, documents, mental models,
  directives, knowledge pages, consolidation, operations retry/cancel, bank name/mission,
  bank config (except `audit_log_enabled`), import, aliases, and deleting any of that content.
- **manage**: visibility, owner and grants; webhooks (create/update/delete and listing them or
  their deliveries); reading the bank's audit log.
- **delete_bank**.

Roles:

| Role | read | write | manage | delete_bank |
|---|---|---|---|---|
| Reader | ✓ | | | |
| Writer | ✓ | ✓ | | |
| Owner | ✓ | ✓ | ✓ | private banks only |
| Admin (global) | ✓ | ✓ | ✓ | ✓ |
| Any authenticated principal, on a **public** bank | ✓ | ✓ | | |
| Anonymous (optional mode), on a public bank | ✓ | ✓ | | |

Effective role = the highest of: owner, direct grant, team grants, implicit public access, Admin.

Rules:
- Any authenticated principal (or anonymous, in optional mode) can create a bank, including by
  auto-creation on first retain. **New banks are public.** The creating principal becomes owner
  (anonymous-created banks have no owner). Ownership is recorded first-writer-wins: concurrent
  first creates may both pass validation; the first ACL row recorded wins.
- A bank with no ACL row (should not exist after migration) is treated as private with no owner:
  admin-only. Fail closed.
- Only Owner or Admin change visibility, owner and grants. An Owner can transfer ownership.
- A **public** bank can be deleted only by an Admin; a **private** bank by its Owner or an Admin.
  (An owner can make a public bank private and then delete it; accepted.)
- The bank list shows each principal only the banks they can read. Admins see all.
- A request on a bank the caller cannot read returns **404**; one the caller can read but lacks
  the capability for returns **403**.
- Bank ids are global: retaining into someone else's private bank returns 404 and does not
  re-create it.
- `audit_log_enabled` is never writable per bank by non-admins.

## Authentication

The API accepts two kinds of bearer credential on HTTP and MCP:
1. **OIDC ID tokens** from the configured issuer and audience(s), verified against the issuer's
   JWKS; `email_verified` must be true and the email domain allowed. The control plane sends the
   logged-in user's ID token on every proxied call. Nothing else in a request asserts identity.
2. **Opaque API tokens** (`hsp_...`), stored hashed, with name, optional expiry, last-used time
   and revocation. Users mint their own; admins mint service-account tokens. A token acts as
   its principal.

Upstream's `HINDSIGHT_API_MCP_AUTH_TOKEN` bypasses tenant authentication: the fork refuses to
start with it set. MCP tool listing hides tools the caller can't use on the target bank when the
bank is in the path (`/mcp/{bank_id}/`); on the multi-bank `/mcp` endpoint every tool call is
still checked against its own bank. Tool filtering fails closed.

Background worker jobs run as the principal that queued them; permissions are re-checked when
the job executes. Jobs queued anonymously are marked as such and do not pass as system jobs.

## Web UI (control plane)

- Replace the shared access-key login with OIDC login and a per-user session.
- Every proxied API call carries the logged-in user's ID token, never a shared key.
- New screens: **My tokens**; **Bank sharing** (visibility, owner, grants); **Admin › Users &
  service accounts** (promote/demote, disable/enable, service-account tokens); **Admin › Teams**.
- Hide or disable actions the user may not perform; the API remains the enforcement point.
- Follow the existing control plane look. No redesign.

## Audit

- Audit logging is on for every bank (deployment config) with **90-day retention**.
- Every audit entry records the acting principal (`anonymous` in grace mode, `system` for
  internal jobs).
- RBAC changes (visibility, owner, grants, teams, admin status, disablement, token create/revoke)
  are audited.
- Only Owner or Admin may read a bank's audit log.

## Migration and switch-over

0. **Upgrade first.** Production runs an older upstream release than this fork's base. Upgrade
   production to the upstream release the fork is based on, as its own change with a database
   snapshot and a rollback plan, before any RBAC change ships.
1. **Existing banks become public with no owner.** Everyone keeps today's access. Bank data is
   not moved, renamed or modified.
2. **Grace mode.** Auth mode is `optional` or `required`.
   - `optional`: a request with no credential is anonymous (public banks only), and every
     anonymous operation is logged with operation, bank, source IP and user-agent.
   - A request with an invalid, expired or revoked credential always gets 401, in either mode.
   - `required`: anonymous requests get 401.
3. Rollout: deploy in `optional`; create service accounts for bots; announce; people log in,
   create tokens and set them in their agent config; watch anonymous logs drop to zero; flip to
   `required`.
4. All deployment changes go through GitOps PRs, never direct cluster changes.

## How it gets made

- **Shape**: an extension package `hindsight-extensions/rbac` (tenant, operation-validator and
  HTTP extensions, its own Alembic tree), shipped in a derived image, plus small documented core
  patches: audit actor, an audit-log read operation for the validator, fail-closed MCP tool
  filtering. Control plane changes are fork patches.
- **Deployment**: upstream Helm chart via values; images built from the fork; OIDC client
  settings through the existing secret pattern.
- **Tests**: upstream conventions (pytest + embedded pg0; control plane's test setup), plus an
  RBAC sweep proving each route and MCP tool asks for the right capability, and one blackbox
  story in `hindsight-system-tests`.

## Left to the builder

- Session mechanics in the control plane; token format details; UI layout of new screens.
- Extension package internals and env variable names.
- Image registry and the fork's CI; upstream sync cadence.

## Prerequisites outside the code

- A Google OAuth client (web application) for the UI host.
- Initial admin emails.
- A service account for each bot before flipping to `required`.
