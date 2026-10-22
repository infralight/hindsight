"use client";

/** fork(rbac): who is signed in (per-user sessions); renders nothing otherwise. */

import { useEffect, useState } from "react";
import { useTranslations } from "next-intl";
import { UserRound } from "lucide-react";
import { withBasePath } from "@/lib/base-path";

interface Me {
  name: string;
  email: string | null;
  is_admin: boolean;
}

export function SignedInUser() {
  const t = useTranslations("nav");
  const [me, setMe] = useState<Me | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    fetch(withBasePath("/api/auth/me"), { signal: controller.signal })
      .then((res) => (res.ok ? res.json() : null))
      .then((body) => setMe(body?.user ?? null))
      .catch(() => {});
    return () => controller.abort();
  }, []);

  if (!me) return null;
  return (
    <span
      className="flex items-center gap-1.5 text-sm text-muted-foreground"
      title={t("signedInAs", { name: me.email ?? me.name })}
    >
      <UserRound className="h-4 w-4" />
      <span className="max-w-[12rem] truncate font-medium text-foreground">{me.name}</span>
      {me.is_admin && (
        <span className="rounded bg-primary/10 px-1.5 py-0.5 text-xs text-primary">admin</span>
      )}
    </span>
  );
}
