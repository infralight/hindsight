import { notFound } from "next/navigation";
import { MyTokens } from "@/components/rbac/my-tokens";

/** fork(rbac): the signed-in user's API tokens. Exists only in rbac mode. */
export const dynamic = "force-dynamic";

export default function TokensPage() {
  if (process.env.HINDSIGHT_CP_AUTH_MODE !== "rbac") notFound();
  return <MyTokens />;
}
