"use client";

/** fork(rbac): a one-field dialog for naming a team or a service account. */

import { useEffect, useState, type FormEvent } from "react";
import { useTranslations } from "next-intl";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Spinner } from "@/components/ui/spinner";

interface NameDialogProps {
  open: boolean;
  title: string;
  confirmLabel: string;
  initial?: string;
  /** Throws to keep the dialog open (the API client has shown why). */
  onSubmit: (name: string) => Promise<void>;
  onClose: () => void;
}

export function NameDialog({
  open,
  title,
  confirmLabel,
  initial = "",
  onSubmit,
  onClose,
}: NameDialogProps) {
  const t = useTranslations("rbac.admin");
  const [name, setName] = useState(initial);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (open) setName(initial);
  }, [open, initial]);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setSaving(true);
    try {
      await onSubmit(name.trim());
      onClose();
    } catch {
      // Stay open so the name can be fixed.
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={(next) => !next && onClose()}>
      <DialogContent>
        <form className="space-y-4" onSubmit={handleSubmit}>
          <DialogHeader>
            <DialogTitle>{title}</DialogTitle>
          </DialogHeader>
          <div className="space-y-2">
            <Label htmlFor="rbac-name">{t("name")}</Label>
            <Input
              id="rbac-name"
              value={name}
              maxLength={200}
              onChange={(e) => setName(e.target.value)}
              autoFocus
            />
          </div>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose}>
              {t("cancel")}
            </Button>
            <Button type="submit" disabled={!name.trim() || saving}>
              {saving && <Spinner size="sm" className="mr-2" />}
              {confirmLabel}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
