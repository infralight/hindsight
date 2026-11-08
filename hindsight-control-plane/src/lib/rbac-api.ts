/**
 * fork(rbac): typed client for /api/rbac (proxied to the dataplane's /ext/rbac).
 * Types mirror hindsight-extensions/rbac/hindsight_ext_rbac/http.py; list endpoints are
 * unwrapped from their `{tokens|principals|teams: [...]}` envelopes.
 */

import { client } from "./api";

export type Role = "reader" | "writer" | "owner";
export type Capability = "read" | "write" | "manage" | "delete_bank";
export type GranteeType = "principal" | "team";

export interface Principal {
  id: string;
  kind: "user" | "service";
  email: string | null;
  name: string;
  is_admin: boolean;
}

export interface PrincipalAdmin extends Principal {
  disabled: boolean;
  is_bootstrap_admin: boolean;
  created_at: string;
  last_seen_at: string | null;
}

export interface Token {
  id: string;
  name: string;
  prefix: string;
  created_at: string;
  expires_at: string | null;
  last_used_at: string | null;
  revoked: boolean;
}

export interface NewToken {
  id: string;
  name: string;
  prefix: string;
  token: string;
  expires_at: string | null;
}

export interface Team {
  id: string;
  name: string;
}

export interface TeamWithMembers extends Team {
  members: Principal[];
}

export interface Directory {
  principals: Principal[];
  teams: Team[];
}

export interface Grant {
  principal_type: GranteeType;
  principal_id: string;
  name: string;
  role: Role;
}

export interface BankAccess {
  bank_id: string;
  visibility: "private" | "public";
  owner: Principal | null;
  grants: Grant[];
  my_role: Role | null;
  my_capabilities: Capability[];
}

const enc = encodeURIComponent;

function call<T>(path: string, method = "GET", body?: unknown): Promise<T> {
  return client.fetchApi<T>(`/api/rbac${path}`, {
    method,
    cache: "no-store",
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}

export const rbac = {
  me: () => call<Principal>("/me"),
  directory: (q: string) => call<Directory>(`/directory?q=${enc(q)}`),

  listTokens: () => call<{ tokens: Token[] }>("/tokens").then((r) => r.tokens),
  createToken: (name: string, expiresAt?: string) =>
    call<NewToken>("/tokens", "POST", { name, expires_at: expiresAt ?? null }),
  revokeToken: (id: string) => call<void>(`/tokens/${enc(id)}`, "DELETE"),

  listPrincipals: () =>
    call<{ principals: PrincipalAdmin[] }>("/principals").then((r) => r.principals),
  updatePrincipal: (id: string, patch: { is_admin?: boolean; disabled?: boolean }) =>
    call<PrincipalAdmin>(`/principals/${enc(id)}`, "PATCH", patch),
  createServiceAccount: (name: string) => call<Principal>("/service-accounts", "POST", { name }),
  listPrincipalTokens: (id: string) =>
    call<{ tokens: Token[] }>(`/principals/${enc(id)}/tokens`).then((r) => r.tokens),
  createPrincipalToken: (id: string, name: string, expiresAt?: string) =>
    call<NewToken>(`/principals/${enc(id)}/tokens`, "POST", {
      name,
      expires_at: expiresAt ?? null,
    }),

  listTeams: () => call<{ teams: TeamWithMembers[] }>("/teams").then((r) => r.teams),
  createTeam: (name: string) => call<Team>("/teams", "POST", { name }),
  renameTeam: (id: string, name: string) => call<Team>(`/teams/${enc(id)}`, "PATCH", { name }),
  deleteTeam: (id: string) => call<void>(`/teams/${enc(id)}`, "DELETE"),
  addMember: (teamId: string, principalId: string) =>
    call<void>(`/teams/${enc(teamId)}/members/${enc(principalId)}`, "PUT"),
  removeMember: (teamId: string, principalId: string) =>
    call<void>(`/teams/${enc(teamId)}/members/${enc(principalId)}`, "DELETE"),

  getAccess: (bankId: string) => call<BankAccess>(`/banks/${enc(bankId)}/access`),
  updateAccess: (bankId: string, patch: { visibility?: "private" | "public"; owner_id?: string }) =>
    call<BankAccess>(`/banks/${enc(bankId)}/access`, "PATCH", patch),
  putGrant: (
    bankId: string,
    grant: { principal_type: GranteeType; principal_id: string; role: Role }
  ) => call<BankAccess>(`/banks/${enc(bankId)}/grants`, "PUT", grant),
  deleteGrant: (bankId: string, type: GranteeType, id: string) =>
    call<void>(`/banks/${enc(bankId)}/grants/${type}/${enc(id)}`, "DELETE"),
};
