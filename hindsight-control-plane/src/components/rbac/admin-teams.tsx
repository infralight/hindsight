"use client";

/**
 * fork(rbac): Admin › Teams. Teams are managed in Hindsight: admins create, rename and
 * delete them and choose their members; banks are then shared with a team as a whole.
 */

import { useCallback, useEffect, useState } from "react";
import { useTranslations } from "next-intl";
import { Pencil, Plus, Trash2, Users, X } from "lucide-react";
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
import { Spinner } from "@/components/ui/spinner";
import { DirectoryPicker } from "@/components/rbac/directory-picker";
import { NameDialog } from "@/components/rbac/name-dialog";
import { rbac, type TeamWithMembers } from "@/lib/rbac-api";

export function AdminTeams() {
  const t = useTranslations("rbac.admin");
  const [teams, setTeams] = useState<TeamWithMembers[] | null>(null);
  // undefined: closed; null: creating; a team: renaming it.
  const [naming, setNaming] = useState<TeamWithMembers | null | undefined>(undefined);
  const [toDelete, setToDelete] = useState<TeamWithMembers | null>(null);

  const reload = useCallback(
    () =>
      rbac.listTeams().then(setTeams, () => {
        setTeams((current) => current ?? []); // the client already showed the error
      }),
    []
  );

  useEffect(() => {
    reload();
  }, [reload]);

  /** Membership answers 204, so every change re-reads the list. */
  const change = async (op: () => Promise<unknown>) => {
    try {
      await op();
    } catch {
      // The client already showed the error.
    }
    await reload();
  };

  const saveName = async (name: string) => {
    if (naming) await rbac.renameTeam(naming.id, name);
    else await rbac.createTeam(name);
    await reload();
  };

  return (
    <div className="space-y-3">
      <div className="flex justify-end">
        <Button size="sm" onClick={() => setNaming(null)} aria-label={t("newTeam")}>
          <Plus className="mr-1.5 h-4 w-4" />
          {t("newTeam")}
        </Button>
      </div>

      {teams === null ? (
        <div className="flex justify-center py-10">
          <Spinner />
        </div>
      ) : teams.length === 0 ? (
        <Card className="bg-muted/20 border-border/40">
          <p className="flex items-center justify-center gap-2 py-10 text-sm text-muted-foreground">
            <Users className="h-4 w-4" />
            {t("noTeams")}
          </p>
        </Card>
      ) : (
        teams.map((team) => (
          <Card key={team.id} className="space-y-3 bg-muted/20 border-border/40 p-4">
            <div className="flex items-center justify-between gap-2">
              <h3 className="flex min-w-0 items-center gap-2 font-medium">
                <Users className="h-4 w-4 shrink-0 text-muted-foreground" />
                <span className="truncate">{team.name}</span>
                <span className="text-xs font-normal text-muted-foreground">
                  {t("memberCount", { count: team.members.length })}
                </span>
              </h3>
              <div className="flex shrink-0 gap-1">
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-8 w-8"
                  aria-label={t("renameTeam")}
                  title={t("renameTeam")}
                  onClick={() => setNaming(team)}
                >
                  <Pencil className="h-4 w-4" />
                </Button>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-8 w-8 text-red-600 dark:text-red-400"
                  aria-label={t("deleteTeam")}
                  title={t("deleteTeam")}
                  onClick={() => setToDelete(team)}
                >
                  <Trash2 className="h-4 w-4" />
                </Button>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              {team.members.map((member) => (
                <span
                  key={member.id}
                  className="inline-flex items-center gap-1 rounded-full border border-border bg-background py-0.5 pl-2.5 pr-1 text-xs"
                  title={member.email ?? undefined}
                >
                  {member.name}
                  <button
                    type="button"
                    className="rounded-full p-0.5 text-muted-foreground hover:bg-accent hover:text-foreground"
                    aria-label={t("removeMember", { name: member.name })}
                    onClick={() => change(() => rbac.removeMember(team.id, member.id))}
                  >
                    <X className="h-3 w-3" />
                  </button>
                </span>
              ))}
              <DirectoryPicker
                kinds={["principal"]}
                exclude={new Set(team.members.map((m) => m.id))}
                onPick={(picked) => change(() => rbac.addMember(team.id, picked.id))}
                placeholder={t("addMember")}
              />
            </div>
          </Card>
        ))
      )}

      <NameDialog
        open={naming !== undefined}
        title={naming ? t("renameTeam") : t("newTeam")}
        confirmLabel={naming ? t("save") : t("create")}
        initial={naming?.name ?? ""}
        onSubmit={saveName}
        onClose={() => setNaming(undefined)}
      />

      <AlertDialog open={toDelete !== null} onOpenChange={(open) => !open && setToDelete(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t("deleteTeamTitle")}</AlertDialogTitle>
            <AlertDialogDescription>
              {t("deleteTeamDescription", { name: toDelete?.name ?? "" })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t("cancel")}</AlertDialogCancel>
            <AlertDialogAction
              className="bg-red-600 text-white hover:bg-red-700"
              onClick={() => {
                const team = toDelete;
                setToDelete(null);
                if (team) change(() => rbac.deleteTeam(team.id));
              }}
            >
              {t("deleteTeamConfirm")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
