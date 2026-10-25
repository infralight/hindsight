"use client";

/**
 * fork(rbac): what the signed-in user may do on a bank, so screens can hide actions the
 * API would refuse. Outside rbac mode every capability is granted (upstream behaviour)
 * and nothing is fetched; in rbac mode nothing is granted until the access is known.
 */

import { useEffect, useState } from "react";
import { useFeatures } from "@/lib/features-context";
import { rbac, type BankAccess, type Capability } from "@/lib/rbac-api";

export function useBankAccess(bankId: string | null): {
  access: BankAccess | null;
  can: (capability: Capability) => boolean;
  /** For a screen that changed the access itself (the Access tab), so the page follows. */
  setAccess: (access: BankAccess | null) => void;
} {
  const { features } = useFeatures();
  const rbacMode = features?.rbac ?? false;
  const [access, setAccess] = useState<BankAccess | null>(null);

  useEffect(() => {
    setAccess(null);
    if (!rbacMode || !bankId) return;
    let live = true; // a bank switch must not show the previous bank's access
    rbac.getAccess(bankId).then(
      (loaded) => live && setAccess(loaded),
      () => {} // the client already showed the error; nothing is granted
    );
    return () => {
      live = false;
    };
  }, [rbacMode, bankId]);

  const can = (capability: Capability) =>
    features !== null && (!rbacMode || (access?.my_capabilities.includes(capability) ?? false));
  return { access, can, setAccess };
}
