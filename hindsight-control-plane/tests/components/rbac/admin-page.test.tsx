// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";

vi.mock("next-intl", () => ({ useTranslations: () => (key: string) => key }));
vi.mock("next/navigation", () => ({ useSearchParams: () => new URLSearchParams() }));
vi.mock("@/lib/bank-context", () => ({ useBank: () => ({ setCurrentBank: vi.fn() }) }));
vi.mock("@/components/bank-selector", () => ({ BankSelector: () => null }));

const rbac = vi.hoisted(() => ({
  me: vi.fn(),
  listPrincipals: vi.fn(),
  listTeams: vi.fn(),
}));
vi.mock("@/lib/rbac-api", () => ({ rbac }));

import { AdminConsole } from "@/components/rbac/admin-console";

describe("AdminConsole", () => {
  afterEach(() => {
    cleanup();
    Object.values(rbac).forEach((fn) => fn.mockReset());
  });

  it("a non-admin sees an admins-only panel and no list calls are made", async () => {
    rbac.me.mockResolvedValue({
      id: "u1",
      kind: "user",
      email: null,
      name: "Bob",
      is_admin: false,
    });
    render(<AdminConsole />);

    expect(await screen.findByText("adminsOnly")).toBeTruthy();
    expect(rbac.listPrincipals).not.toHaveBeenCalled();
    expect(rbac.listTeams).not.toHaveBeenCalled();
  });

  it("an admin sees the users tab", async () => {
    rbac.me.mockResolvedValue({
      id: "u1",
      kind: "user",
      email: null,
      name: "Root",
      is_admin: true,
    });
    rbac.listPrincipals.mockResolvedValue([]);
    render(<AdminConsole />);

    expect(await screen.findByRole("button", { name: "newServiceAccount" })).toBeTruthy();
    expect(rbac.listTeams).not.toHaveBeenCalled();
  });
});
