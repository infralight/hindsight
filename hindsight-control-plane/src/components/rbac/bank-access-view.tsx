"use client";

/**
 * fork(rbac): who can reach a bank — its visibility, its owner, and the people and teams
 * it is shared with. Only the owner or an admin may change any of it; everyone else sees
 * the same settings read-only. Every change re-renders from the access the API returns,
 * so a caller who gives away their own control drops to read-only at once.
 */

import { useEffect, useState, type ReactNode } from "react";
import { useTranslations } from "next-intl";
import { Lock, Trash2, User, Users } from "lucide-react";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Spinner } from "@/components/ui/spinner";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { DirectoryPicker, type PickedGrantee } from "@/components/rbac/directory-picker";
import { rbac, type BankAccess, type Grant, type Role } from "@/lib/rbac-api";

const ROLES: Role[] = ["reader", "writer", "owner"];

function AccessSection({
  title,
  description,
  children,
}: {
  title: string;
  description: string;
  children: ReactNode;
}) {
  return (
    <section className="space-y-3">
      <div>
        <h2 className="text-lg font-semibold">{title}</h2>
        <p className="text-sm text-muted-foreground">{description}</p>
      </div>
      <Card className="bg-muted/20 border-border/40">{children}</Card>
    </section>
  );
}

function RoleSelect({
  value,
  onChange,
  disabled,
  label,
}: {
  value: Role;
  onChange: (role: Role) => void;
  disabled: boolean;
  label: string;
}) {
  const t = useTranslations("rbac.access");
  return (
    <Select value={value} onValueChange={(v) => onChange(v as Role)} disabled={disabled}>
      <SelectTrigger className="h-8 w-32" aria-label={label}>
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        {ROLES.map((role) => (
          <SelectItem key={role} value={role}>
            {t(`roles.${role}`)}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

export function BankAccessView({ bankId }: { bankId: string }) {
  const t = useTranslations("rbac.access");
  const [access, setAccess] = useState<BankAccess | null>(null);
  const [lost, setLost] = useState(false);
  const [newRole, setNewRole] = useState<Role>("reader");
  const [newOwner, setNewOwner] = useState<PickedGrantee | null>(null);

  useEffect(() => {
    let live = true;
    setAccess(null);
    setLost(false);
    rbac.getAccess(bankId).then(
      (loaded) => live && setAccess(loaded),
      () => live && setLost(true)
    );
    return () => {
      live = false;
    };
  }, [bankId]);

  // Controls stay enabled while a change is in flight: disabling them would drop keyboard
  // focus to the page.
  const mutate = async (change: () => Promise<BankAccess | null>) => {
    try {
      const next = await change();
      if (next) setAccess(next);
    } catch {
      // The API client already showed the error; the settings on screen are unchanged.
    }
  };

  const grant = (type: Grant["principal_type"], id: string, role: Role) =>
    mutate(() => rbac.putGrant(bankId, { principal_type: type, principal_id: id, role }));

  const removeGrant = (g: Grant) =>
    mutate(async () => {
      await rbac.deleteGrant(bankId, g.principal_type, g.principal_id);
      // A delete answers 204; re-read, since removing your own grant may cost you access.
      try {
        return await rbac.getAccess(bankId);
      } catch {
        setLost(true);
        return null;
      }
    });

  if (lost) {
    return <p className="py-12 text-center text-sm text-muted-foreground">{t("noAccess")}</p>;
  }
  if (!access) {
    return (
      <div className="flex justify-center py-12">
        <Spinner />
      </div>
    );
  }

  const canManage = access.my_capabilities.includes("manage");
  const locked = !canManage;
  const granted = new Set(access.grants.map((g) => g.principal_id));

  return (
    <div className="space-y-8">
      {!canManage && (
        <p className="flex items-center gap-2 rounded-md border border-border/40 bg-muted/20 px-4 py-3 text-sm text-muted-foreground">
          <Lock className="h-4 w-4 shrink-0" />
          {t("readOnlyNote")}
        </p>
      )}

      <AccessSection title={t("visibilityTitle")} description={t("visibilityDescription")}>
        <div className="flex flex-col gap-3 p-6 sm:flex-row sm:items-center sm:justify-between">
          <p className="text-sm text-muted-foreground">
            {access.visibility === "public" ? t("publicHelp") : t("privateHelp")}
          </p>
          <Select
            value={access.visibility}
            onValueChange={(v) =>
              mutate(() => rbac.updateAccess(bankId, { visibility: v as BankAccess["visibility"] }))
            }
            disabled={locked}
          >
            <SelectTrigger className="w-40" aria-label={t("visibility")}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="private">{t("visibilityPrivate")}</SelectItem>
              <SelectItem value="public">{t("visibilityPublic")}</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </AccessSection>

      <AccessSection title={t("ownerTitle")} description={t("ownerDescription")}>
        <div className="flex flex-col gap-3 p-6 sm:flex-row sm:items-center sm:justify-between">
          {access.owner ? (
            <div className="min-w-0">
              <p className="truncate text-sm font-medium">{access.owner.name}</p>
              {access.owner.email && (
                <p className="truncate text-sm text-muted-foreground">{access.owner.email}</p>
              )}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">{t("noOwner")}</p>
          )}
          <DirectoryPicker
            kinds={["principal"]}
            exclude={new Set(access.owner ? [access.owner.id] : [])}
            onPick={setNewOwner}
            placeholder={t("transferOwnership")}
            disabled={locked}
          />
        </div>
      </AccessSection>

      <AccessSection title={t("grantsTitle")} description={t("grantsDescription")}>
        {access.grants.length === 0 ? (
          <p className="px-6 pt-6 text-sm text-muted-foreground">{t("noGrants")}</p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="pl-6">{t("name")}</TableHead>
                <TableHead>{t("role")}</TableHead>
                <TableHead className="w-12 pr-6" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {access.grants.map((g) => (
                <TableRow key={`${g.principal_type}:${g.principal_id}`}>
                  <TableCell className="pl-6">
                    <span className="flex items-center gap-2">
                      {g.principal_type === "team" ? (
                        <Users
                          className="h-4 w-4 text-muted-foreground"
                          aria-label={t("kindTeam")}
                        />
                      ) : (
                        <User
                          className="h-4 w-4 text-muted-foreground"
                          aria-label={t("kindPerson")}
                        />
                      )}
                      {g.name}
                    </span>
                  </TableCell>
                  <TableCell>
                    <RoleSelect
                      value={g.role}
                      onChange={(role) => grant(g.principal_type, g.principal_id, role)}
                      disabled={locked}
                      label={t("role")}
                    />
                  </TableCell>
                  <TableCell className="pr-6">
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-8 w-8"
                      disabled={locked}
                      aria-label={t("remove")}
                      title={t("remove")}
                      onClick={() => removeGrant(g)}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
        <div className="flex flex-wrap items-center gap-2 p-6">
          <RoleSelect
            value={newRole}
            onChange={setNewRole}
            disabled={locked}
            label={t("newRole")}
          />
          <DirectoryPicker
            kinds={["principal", "team"]}
            exclude={granted}
            onPick={(picked) => grant(picked.type, picked.id, newRole)}
            placeholder={t("addPeople")}
            disabled={locked}
          />
        </div>
      </AccessSection>

      <AlertDialog open={newOwner !== null} onOpenChange={(open) => !open && setNewOwner(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t("transferTitle")}</AlertDialogTitle>
            <AlertDialogDescription>
              {t("transferDescription", { name: newOwner?.name ?? "" })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t("cancel")}</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                const owner = newOwner;
                setNewOwner(null);
                if (owner) mutate(() => rbac.updateAccess(bankId, { owner_id: owner.id }));
              }}
            >
              {t("transferConfirm")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
