"use client";

/**
 * fork(rbac): who is signed in (per-user sessions), as a menu to their API tokens and,
 * for admins, the Admin page. Renders nothing without a per-user session.
 */

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { ChevronDown, KeyRound, ShieldCheck, UserRound } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { withBasePath } from "@/lib/base-path";

interface Me {
  name: string;
  email: string | null;
  is_admin: boolean;
}

export function SignedInUser() {
  const t = useTranslations("nav");
  const router = useRouter();
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
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          size="sm"
          className="gap-1.5 px-2 text-muted-foreground"
          title={t("signedInAs", { name: me.email ?? me.name })}
        >
          <UserRound className="h-4 w-4" />
          <span className="max-w-[12rem] truncate font-medium text-foreground">{me.name}</span>
          {me.is_admin && (
            <span className="rounded bg-primary/10 px-1.5 py-0.5 text-xs text-primary">admin</span>
          )}
          <ChevronDown className="h-3.5 w-3.5" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-56">
        <div className="px-2 py-1.5">
          <p className="truncate text-sm font-medium">{me.name}</p>
          {me.email && <p className="truncate text-xs text-muted-foreground">{me.email}</p>}
        </div>
        <DropdownMenuSeparator />
        <DropdownMenuItem onSelect={() => router.push("/tokens")}>
          <KeyRound className="mr-2 h-4 w-4" />
          {t("myTokens")}
        </DropdownMenuItem>
        {me.is_admin && (
          <DropdownMenuItem onSelect={() => router.push("/admin")}>
            <ShieldCheck className="mr-2 h-4 w-4" />
            {t("admin")}
          </DropdownMenuItem>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
