"use client";

/**
 * fork(rbac): Admin › Users & service accounts. Admins grant or remove the admin role,
 * disable or re-enable accounts, and create service accounts and their tokens. The
 * actions the API refuses (demoting or disabling a configured admin, making a service
 * account an admin) are disabled here with the reason as a tooltip.
 */

import { Fragment, useCallback, useEffect, useState } from "react";
import { useTranslations } from "next-intl";
import { Bot, Plus, User } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Spinner } from "@/components/ui/spinner";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { NameDialog } from "@/components/rbac/name-dialog";
import { TokenList } from "@/components/rbac/token-list";
import { formatRelativeTime } from "@/lib/relative-time";
import { rbac, type PrincipalAdmin } from "@/lib/rbac-api";

function ServiceAccountTokens({ id }: { id: string }) {
  const load = useCallback(() => rbac.listPrincipalTokens(id), [id]);
  const create = useCallback(
    (name: string, expiresAt?: string) => rbac.createPrincipalToken(id, name, expiresAt),
    [id]
  );
  return <TokenList load={load} create={create} revoke={rbac.revokeToken} />;
}

/** A disabled button shows no tooltip, so the reason sits on a wrapper. */
function Guarded({ reason, children }: { reason: string | null; children: React.ReactNode }) {
  return reason ? <span title={reason}>{children}</span> : <>{children}</>;
}

export function AdminUsers() {
  const t = useTranslations("rbac.admin");
  const [principals, setPrincipals] = useState<PrincipalAdmin[] | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);

  const reload = useCallback(
    () =>
      rbac.listPrincipals().then(setPrincipals, () => {
        setPrincipals((current) => current ?? []); // the client already showed the error
      }),
    []
  );

  useEffect(() => {
    reload();
  }, [reload]);

  const update = async (
    target: PrincipalAdmin,
    patch: { is_admin?: boolean; disabled?: boolean }
  ) => {
    try {
      const next = await rbac.updatePrincipal(target.id, patch);
      setPrincipals((list) => list?.map((p) => (p.id === next.id ? next : p)) ?? null);
    } catch {
      // The client already showed the error.
    }
  };

  const createServiceAccount = async (name: string) => {
    const account = await rbac.createServiceAccount(name);
    await reload();
    setExpanded(account.id); // a new service account is only useful once it has a token
  };

  return (
    <div className="space-y-3">
      <div className="flex justify-end">
        <Button size="sm" onClick={() => setCreating(true)} aria-label={t("newServiceAccount")}>
          <Plus className="mr-1.5 h-4 w-4" />
          {t("newServiceAccount")}
        </Button>
      </div>

      <Card className="bg-muted/20 border-border/40">
        {principals === null ? (
          <div className="flex justify-center py-10">
            <Spinner />
          </div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="pl-6">{t("name")}</TableHead>
                <TableHead>{t("kind")}</TableHead>
                <TableHead>{t("statusLabel")}</TableHead>
                <TableHead>{t("lastSeen")}</TableHead>
                <TableHead className="pr-6 text-right">{t("actions")}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {principals.map((p) => {
                const isService = p.kind === "service";
                const adminLock = p.is_bootstrap_admin
                  ? t("bootstrapLocked")
                  : isService && !p.is_admin
                    ? t("serviceNoAdmin")
                    : null;
                const disableLock =
                  p.is_bootstrap_admin && !p.disabled ? t("bootstrapLocked") : null;
                return (
                  <Fragment key={p.id}>
                    <TableRow className={p.disabled ? "opacity-60" : undefined}>
                      <TableCell className="pl-6">
                        <div className="flex items-center gap-2">
                          {isService ? (
                            <Bot className="h-4 w-4 shrink-0 text-muted-foreground" />
                          ) : (
                            <User className="h-4 w-4 shrink-0 text-muted-foreground" />
                          )}
                          <div className="min-w-0">
                            <p className="flex items-center gap-2 truncate font-medium">
                              {p.name}
                              {p.is_admin && (
                                <span className="rounded-full bg-primary/10 px-2 py-0.5 text-[11px] font-medium text-primary">
                                  {t("adminBadge")}
                                </span>
                              )}
                            </p>
                            {p.email && (
                              <p className="truncate text-xs text-muted-foreground">{p.email}</p>
                            )}
                          </div>
                        </div>
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {isService ? t("kindService") : t("kindUser")}
                      </TableCell>
                      <TableCell className="text-sm">
                        {p.disabled ? t("status.disabled") : t("status.active")}
                      </TableCell>
                      <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
                        {p.last_seen_at ? formatRelativeTime(p.last_seen_at) : t("never")}
                      </TableCell>
                      <TableCell className="pr-6">
                        <div className="flex flex-wrap justify-end gap-1">
                          {isService && (
                            <Button
                              variant="ghost"
                              size="sm"
                              aria-expanded={expanded === p.id}
                              onClick={() => setExpanded(expanded === p.id ? null : p.id)}
                            >
                              {t("tokens")}
                            </Button>
                          )}
                          <Guarded reason={adminLock}>
                            <Button
                              variant="ghost"
                              size="sm"
                              disabled={adminLock !== null}
                              onClick={() => update(p, { is_admin: !p.is_admin })}
                            >
                              {p.is_admin ? t("removeAdmin") : t("makeAdmin")}
                            </Button>
                          </Guarded>
                          <Guarded reason={disableLock}>
                            <Button
                              variant="ghost"
                              size="sm"
                              className={p.disabled ? undefined : "text-red-600 dark:text-red-400"}
                              disabled={disableLock !== null}
                              onClick={() => update(p, { disabled: !p.disabled })}
                            >
                              {p.disabled ? t("enable") : t("disable")}
                            </Button>
                          </Guarded>
                        </div>
                      </TableCell>
                    </TableRow>
                    {expanded === p.id && (
                      <TableRow className="bg-muted/20 hover:bg-muted/20">
                        <TableCell colSpan={5} className="px-6 py-4">
                          <ServiceAccountTokens id={p.id} />
                        </TableCell>
                      </TableRow>
                    )}
                  </Fragment>
                );
              })}
            </TableBody>
          </Table>
        )}
      </Card>

      <NameDialog
        open={creating}
        title={t("newServiceAccount")}
        confirmLabel={t("create")}
        onSubmit={createServiceAccount}
        onClose={() => setCreating(false)}
      />
    </div>
  );
}
