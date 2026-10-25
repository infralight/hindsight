"use client";

/**
 * fork(rbac): API tokens for agents, MCP clients and scripts — your own on the My tokens
 * page, a service account's on the admin page. A new token's secret is shown once, in
 * the dialog that created it, and dropped from memory when that dialog closes.
 */

import { useCallback, useEffect, useState } from "react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";
import { Copy, KeyRound, Plus } from "lucide-react";
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
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Spinner } from "@/components/ui/spinner";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { formatRelativeTime } from "@/lib/relative-time";
import type { NewToken, Token } from "@/lib/rbac-api";

interface TokenListProps {
  load: () => Promise<Token[]>;
  create: (name: string, expiresAt?: string) => Promise<NewToken>;
  revoke: (id: string) => Promise<void>;
}

function tokenStatus(token: Token): "revoked" | "expired" | "active" {
  if (token.revoked) return "revoked";
  if (token.expires_at && new Date(token.expires_at).getTime() <= Date.now()) return "expired";
  return "active";
}

const STATUS_CLASS = {
  active: "text-emerald-700 dark:text-emerald-400",
  expired: "text-muted-foreground",
  revoked: "text-muted-foreground line-through",
};

export function TokenList({ load, create, revoke }: TokenListProps) {
  const t = useTranslations("rbac.tokens");
  const [tokens, setTokens] = useState<Token[] | null>(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [name, setName] = useState("");
  const [expiresOn, setExpiresOn] = useState("");
  const [saving, setSaving] = useState(false);
  const [created, setCreated] = useState<NewToken | null>(null);
  const [toRevoke, setToRevoke] = useState<Token | null>(null);

  const reload = useCallback(
    () =>
      load().then(setTokens, () => {
        setTokens((current) => current ?? []); // the client already showed the error
      }),
    [load]
  );

  useEffect(() => {
    reload();
  }, [reload]);

  const closeDialog = () => {
    setDialogOpen(false);
    setCreated(null); // the secret leaves memory with the dialog
    setName("");
    setExpiresOn("");
  };

  const handleCreate = async () => {
    setSaving(true);
    try {
      // An expiry date means the end of that day, local time.
      const expiresAt = expiresOn ? new Date(`${expiresOn}T23:59:59`).toISOString() : undefined;
      setCreated(await create(name.trim(), expiresAt));
      reload();
    } catch {
      // The client already showed the error; the form stays open to retry.
    } finally {
      setSaving(false);
    }
  };

  const handleRevoke = async (token: Token) => {
    setToRevoke(null);
    try {
      await revoke(token.id);
    } catch {
      // The client already showed the error.
    }
    reload();
  };

  const copySecret = (secret: string) =>
    navigator.clipboard.writeText(secret).then(
      () => toast.success(t("copied")),
      () => toast.error(t("copyFailed"))
    );

  return (
    <div className="space-y-3">
      <div className="flex justify-end">
        <Button size="sm" onClick={() => setDialogOpen(true)} aria-label={t("newToken")}>
          <Plus className="mr-1.5 h-4 w-4" />
          {t("newToken")}
        </Button>
      </div>

      <Card className="bg-muted/20 border-border/40">
        {tokens === null ? (
          <div className="flex justify-center py-10">
            <Spinner />
          </div>
        ) : tokens.length === 0 ? (
          <p className="flex items-center justify-center gap-2 py-10 text-sm text-muted-foreground">
            <KeyRound className="h-4 w-4" />
            {t("empty")}
          </p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="pl-6">{t("name")}</TableHead>
                <TableHead>{t("token")}</TableHead>
                <TableHead>{t("created")}</TableHead>
                <TableHead>{t("lastUsed")}</TableHead>
                <TableHead>{t("expires")}</TableHead>
                <TableHead>{t("statusLabel")}</TableHead>
                <TableHead className="w-24 pr-6" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {tokens.map((token) => {
                const status = tokenStatus(token);
                return (
                  <TableRow key={token.id}>
                    <TableCell className="pl-6 font-medium">{token.name}</TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {token.prefix}…
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
                      {formatRelativeTime(token.created_at)}
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
                      {token.last_used_at ? formatRelativeTime(token.last_used_at) : t("never")}
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
                      {token.expires_at
                        ? new Date(token.expires_at).toLocaleDateString()
                        : t("never")}
                    </TableCell>
                    <TableCell className={`text-xs ${STATUS_CLASS[status]}`}>
                      {t(`status.${status}`)}
                    </TableCell>
                    <TableCell className="pr-6 text-right">
                      {status === "active" && (
                        <Button
                          variant="ghost"
                          size="sm"
                          className="text-red-600 dark:text-red-400"
                          aria-label={t("revoke")}
                          onClick={() => setToRevoke(token)}
                        >
                          {t("revoke")}
                        </Button>
                      )}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        )}
      </Card>

      <Dialog
        open={dialogOpen}
        onOpenChange={(open) => (open ? setDialogOpen(true) : closeDialog())}
      >
        <DialogContent>
          {created ? (
            <>
              <DialogHeader>
                <DialogTitle>{t("createdTitle")}</DialogTitle>
                <DialogDescription>{t("createdWarning")}</DialogDescription>
              </DialogHeader>
              <div className="flex gap-2">
                <Input
                  readOnly
                  value={created.token}
                  aria-label={t("token")}
                  className="font-mono text-xs"
                  onFocus={(e) => e.currentTarget.select()}
                />
                <Button
                  variant="outline"
                  size="icon"
                  aria-label={t("copy")}
                  title={t("copy")}
                  onClick={() => copySecret(created.token)}
                >
                  <Copy className="h-4 w-4" />
                </Button>
              </div>
              <DialogFooter>
                <Button onClick={closeDialog}>{t("done")}</Button>
              </DialogFooter>
            </>
          ) : (
            <form
              className="space-y-4"
              onSubmit={(e) => {
                e.preventDefault();
                handleCreate();
              }}
            >
              <DialogHeader>
                <DialogTitle>{t("newToken")}</DialogTitle>
                <DialogDescription>{t("newTokenDescription")}</DialogDescription>
              </DialogHeader>
              <div className="space-y-2">
                <Label htmlFor="token-name">{t("name")}</Label>
                <Input
                  id="token-name"
                  value={name}
                  maxLength={200}
                  placeholder={t("namePlaceholder")}
                  onChange={(e) => setName(e.target.value)}
                  autoFocus
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="token-expires">{t("expiresOn")}</Label>
                <Input
                  id="token-expires"
                  type="date"
                  value={expiresOn}
                  min={new Date().toISOString().slice(0, 10)}
                  onChange={(e) => setExpiresOn(e.target.value)}
                />
                <p className="text-xs text-muted-foreground">{t("expiresHelp")}</p>
              </div>
              <DialogFooter>
                <Button type="button" variant="outline" onClick={closeDialog}>
                  {t("cancel")}
                </Button>
                <Button type="submit" disabled={!name.trim() || saving}>
                  {saving && <Spinner size="sm" className="mr-2" />}
                  {t("create")}
                </Button>
              </DialogFooter>
            </form>
          )}
        </DialogContent>
      </Dialog>

      <AlertDialog open={toRevoke !== null} onOpenChange={(open) => !open && setToRevoke(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t("revokeTitle")}</AlertDialogTitle>
            <AlertDialogDescription>
              {t("revokeDescription", { name: toRevoke?.name ?? "" })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t("cancel")}</AlertDialogCancel>
            <AlertDialogAction
              className="bg-red-600 text-white hover:bg-red-700"
              onClick={() => toRevoke && handleRevoke(toRevoke)}
            >
              {t("revokeConfirm")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
