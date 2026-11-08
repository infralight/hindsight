import { notFound } from "next/navigation";
import { AdminConsole } from "@/components/rbac/admin-console";

/** fork(rbac): users, service accounts and teams. Exists only in rbac mode. */
export const dynamic = "force-dynamic";

export default function AdminPage() {
  if (process.env.HINDSIGHT_CP_AUTH_MODE !== "rbac") notFound();
  return <AdminConsole />;
}
