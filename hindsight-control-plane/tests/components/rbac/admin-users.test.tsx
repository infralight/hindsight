// @vitest-environment jsdom
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import type { PrincipalAdmin } from "@/lib/rbac-api";
import { stubLayoutApis } from "./radix-jsdom";

vi.mock("next-intl", () => ({ useTranslations: () => (key: string) => key }));
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

const rbac = vi.hoisted(() => ({
  listPrincipals: vi.fn(),
  updatePrincipal: vi.fn(),
  createServiceAccount: vi.fn(),
  listPrincipalTokens: vi.fn(),
  createPrincipalToken: vi.fn(),
  revokeToken: vi.fn(),
}));
vi.mock("@/lib/rbac-api", () => ({ rbac }));

import { AdminUsers } from "@/components/rbac/admin-users";

function principal(over: Partial<PrincipalAdmin>): PrincipalAdmin {
  return {
    id: "u-bob",
    kind: "user",
    email: "bob@x.test",
    name: "Bob",
    is_admin: false,
    disabled: false,
    is_bootstrap_admin: false,
    created_at: "2026-10-01T10:00:00Z",
    last_seen_at: null,
    ...over,
  };
}

const ROOT = principal({ id: "u-root", name: "Root", is_admin: true, is_bootstrap_admin: true });
const BOT = principal({ id: "s-bot", name: "ci-bot", kind: "service", email: null });

const rowOf = async (name: string) => (await screen.findByText(name)).closest("tr") as HTMLElement;

describe("AdminUsers", () => {
  beforeAll(stubLayoutApis);
  afterEach(() => {
    cleanup();
    Object.values(rbac).forEach((fn) => fn.mockReset());
  });

  it("promote is disabled for bootstrap admins and service accounts", async () => {
    rbac.listPrincipals.mockResolvedValue([ROOT, BOT, principal({})]);
    render(<AdminUsers />);

    const root = await rowOf("Root");
    expect(within(root).getByRole("button", { name: "removeAdmin" })).toHaveProperty(
      "disabled",
      true
    );
    expect(within(root).getByRole("button", { name: "disable" })).toHaveProperty("disabled", true);
    expect(within(await rowOf("ci-bot")).getByRole("button", { name: "makeAdmin" })).toHaveProperty(
      "disabled",
      true
    );
    expect(within(await rowOf("Bob")).getByRole("button", { name: "makeAdmin" })).toHaveProperty(
      "disabled",
      false
    );
  });

  it("disabling a user calls updatePrincipal({disabled: true})", async () => {
    rbac.listPrincipals.mockResolvedValue([principal({})]);
    rbac.updatePrincipal.mockResolvedValue(principal({ disabled: true }));
    render(<AdminUsers />);

    fireEvent.click(within(await rowOf("Bob")).getByRole("button", { name: "disable" }));
    await waitFor(() =>
      expect(rbac.updatePrincipal).toHaveBeenCalledWith("u-bob", { disabled: true })
    );
    expect(await within(await rowOf("Bob")).findByRole("button", { name: "enable" })).toBeTruthy();
  });

  it("creating a service account adds its row and opens its tokens", async () => {
    rbac.listPrincipals
      .mockResolvedValueOnce([principal({})])
      .mockResolvedValue([principal({}), BOT]);
    rbac.createServiceAccount.mockResolvedValue({ ...BOT });
    rbac.listPrincipalTokens.mockResolvedValue([]);
    render(<AdminUsers />);
    await screen.findByText("Bob");

    fireEvent.click(screen.getByRole("button", { name: "newServiceAccount" }));
    fireEvent.change(screen.getByLabelText("name"), { target: { value: "ci-bot" } });
    fireEvent.click(screen.getByRole("button", { name: "create" }));

    await waitFor(() => expect(rbac.createServiceAccount).toHaveBeenCalledWith("ci-bot"));
    await screen.findByText("ci-bot");
    await waitFor(() => expect(rbac.listPrincipalTokens).toHaveBeenCalledWith("s-bot"));
  });
});
