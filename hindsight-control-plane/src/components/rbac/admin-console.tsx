"use client";

/**
 * fork(rbac): the Admin page — Users & service accounts, and Teams. A non-admin who
 * opens it gets one explanation instead of a page of refused requests.
 */

import { useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import { useTranslations } from "next-intl";
import { ShieldAlert } from "lucide-react";
import { BankSelector } from "@/components/bank-selector";
import { AdminTeams } from "@/components/rbac/admin-teams";
import { AdminUsers } from "@/components/rbac/admin-users";
import { Spinner } from "@/components/ui/spinner";
import { UnderlineTabs } from "@/components/ui/underline-tabs";
import { useBank } from "@/lib/bank-context";
import { rbac, type Principal } from "@/lib/rbac-api";

type AdminTab = "users" | "teams";

export function AdminConsole() {
  const t = useTranslations("rbac.admin");
  const { setCurrentBank } = useBank();
  const searchParams = useSearchParams();
  const tab: AdminTab = searchParams.get("tab") === "teams" ? "teams" : "users";
  // undefined while loading; null when it could not be read (the client showed why).
  const [me, setMe] = useState<Principal | null | undefined>(undefined);

  // Not a bank page: the header must not offer actions for a bank that is not on screen.
  useEffect(() => {
    setCurrentBank(null);
  }, [setCurrentBank]);

  useEffect(() => {
    rbac.me().then(setMe, () => setMe(null));
  }, []);

  // The history API updates useSearchParams without a router round trip.
  const setTab = (next: AdminTab) => window.history.replaceState(null, "", `?tab=${next}`);

  let body: React.ReactNode;
  if (me === undefined) {
    body = (
      <div className="flex justify-center py-16">
        <Spinner />
      </div>
    );
  } else if (!me?.is_admin) {
    body = (
      <div className="mx-auto mt-10 max-w-md rounded-lg border border-border bg-card p-8 text-center">
        <ShieldAlert className="mx-auto mb-3 h-8 w-8 text-muted-foreground" />
        <h2 className="text-lg font-semibold">{t("adminsOnlyTitle")}</h2>
        <p className="mt-1 text-sm text-muted-foreground">{t("adminsOnly")}</p>
      </div>
    );
  } else {
    body = (
      <>
        <UnderlineTabs
          value={tab}
          onChange={setTab}
          tabs={[
            { id: "users", label: t("usersTab") },
            { id: "teams", label: t("teamsTab") },
          ]}
        />
        {tab === "users" ? <AdminUsers /> : <AdminTeams />}
      </>
    );
  }

  return (
    <div className="min-h-screen bg-background flex flex-col">
      <BankSelector />
      <main className="mx-auto w-full max-w-6xl px-6 py-8">
        <h1 className="text-2xl font-bold text-foreground">{t("title")}</h1>
        <p className="mt-1 mb-6 max-w-2xl text-sm text-muted-foreground">{t("description")}</p>
        {body}
      </main>
    </div>
  );
}
