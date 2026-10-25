"use client";

/** fork(rbac): the My tokens page — the signed-in user's own API tokens. */

import { useEffect } from "react";
import { useTranslations } from "next-intl";
import { BankSelector } from "@/components/bank-selector";
import { TokenList } from "@/components/rbac/token-list";
import { useBank } from "@/lib/bank-context";
import { rbac } from "@/lib/rbac-api";

export function MyTokens() {
  const t = useTranslations("rbac.tokens");
  const { setCurrentBank } = useBank();

  // Not a bank page: the header must not offer actions for a bank that is not on screen.
  useEffect(() => {
    setCurrentBank(null);
  }, [setCurrentBank]);

  return (
    <div className="min-h-screen bg-background flex flex-col">
      <BankSelector />
      <main className="mx-auto w-full max-w-6xl px-6 py-8">
        <h1 className="text-2xl font-bold text-foreground">{t("title")}</h1>
        <p className="mt-1 mb-6 max-w-2xl text-sm text-muted-foreground">{t("description")}</p>
        <TokenList load={rbac.listTokens} create={rbac.createToken} revoke={rbac.revokeToken} />
      </main>
    </div>
  );
}
