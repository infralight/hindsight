// @vitest-environment jsdom
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import type { BankAccess } from "@/lib/rbac-api";
import { chooseOption, stubLayoutApis } from "./radix-jsdom";

vi.mock("next-intl", () => ({ useTranslations: () => (key: string) => key }));

const rbac = vi.hoisted(() => ({
  getAccess: vi.fn(),
  updateAccess: vi.fn(),
  putGrant: vi.fn(),
  deleteGrant: vi.fn(),
  directory: vi.fn(),
}));
vi.mock("@/lib/rbac-api", () => ({ rbac }));

import { BankAccessView } from "@/components/rbac/bank-access-view";

const ALICE = {
  id: "u-alice",
  kind: "user",
  email: "alice@x.test",
  name: "Alice",
  is_admin: false,
};

function access(over: Partial<BankAccess> = {}): BankAccess {
  return {
    bank_id: "b1",
    visibility: "private",
    owner: ALICE,
    grants: [{ principal_type: "principal", principal_id: "u-bob", name: "Bob", role: "reader" }],
    my_role: "owner",
    my_capabilities: ["delete_bank", "manage", "read", "write"],
    ...over,
  } as BankAccess;
}

const READ_ONLY = { my_role: "reader" as const, my_capabilities: ["read" as const] };

async function renderView(initial: BankAccess) {
  rbac.getAccess.mockResolvedValue(initial);
  render(<BankAccessView bankId="b1" />);
  await screen.findByText("Bob");
}

const bobRow = () => screen.getByText("Bob").closest("tr") as HTMLElement;

describe("BankAccessView", () => {
  beforeAll(stubLayoutApis);
  afterEach(() => {
    cleanup();
    Object.values(rbac).forEach((fn) => fn.mockReset());
  });

  it("shows visibility, owner and grants from getAccess", async () => {
    await renderView(access());
    expect(rbac.getAccess).toHaveBeenCalledWith("b1");
    expect(screen.getByText("Alice")).toBeTruthy();
    expect(screen.getByText("alice@x.test")).toBeTruthy();
    expect(screen.getByRole("combobox", { name: "visibility" }).textContent).toContain(
      "visibilityPrivate"
    );
    expect(within(bobRow()).getByRole("combobox").textContent).toContain("roles.reader");
  });

  it("disables every control without the manage capability", async () => {
    await renderView(access(READ_ONLY));
    for (const control of [...screen.getAllByRole("combobox"), ...screen.getAllByRole("button")]) {
      expect(control).toHaveProperty("disabled", true);
    }
    expect(screen.getByText("readOnlyNote")).toBeTruthy();
  });

  it("adding a team as writer calls putGrant with principal_type team and role writer", async () => {
    await renderView(access());
    rbac.directory.mockResolvedValue({ principals: [], teams: [{ id: "t1", name: "Platform" }] });
    rbac.putGrant.mockResolvedValue(access());

    await chooseOption(screen.getByRole("combobox", { name: "newRole" }), "roles.writer");
    fireEvent.click(screen.getByRole("button", { name: "addPeople" }));
    fireEvent.click(await screen.findByText("Platform"));

    await waitFor(() =>
      expect(rbac.putGrant).toHaveBeenCalledWith("b1", {
        principal_type: "team",
        principal_id: "t1",
        role: "writer",
      })
    );
  });

  it("changing a grant's role calls putGrant; removing calls deleteGrant", async () => {
    await renderView(access());
    rbac.putGrant.mockResolvedValue(access());
    await chooseOption(within(bobRow()).getByRole("combobox"), "roles.writer");
    await waitFor(() =>
      expect(rbac.putGrant).toHaveBeenCalledWith("b1", {
        principal_type: "principal",
        principal_id: "u-bob",
        role: "writer",
      })
    );

    rbac.deleteGrant.mockResolvedValue(undefined);
    rbac.getAccess.mockResolvedValue(access({ grants: [] }));
    fireEvent.click(within(bobRow()).getByRole("button", { name: "remove" }));
    await waitFor(() => expect(rbac.deleteGrant).toHaveBeenCalledWith("b1", "principal", "u-bob"));
    await waitFor(() => expect(screen.queryByText("Bob")).toBeNull());
  });

  it("switching to private calls updateAccess", async () => {
    await renderView(access({ visibility: "public" }));
    rbac.updateAccess.mockResolvedValue(access());
    await chooseOption(screen.getByRole("combobox", { name: "visibility" }), "visibilityPrivate");
    await waitFor(() =>
      expect(rbac.updateAccess).toHaveBeenCalledWith("b1", { visibility: "private" })
    );
  });

  it("drops to read-only when the mutation's BankAccess no longer has manage", async () => {
    await renderView(access());
    rbac.putGrant.mockResolvedValue(access(READ_ONLY));
    await chooseOption(within(bobRow()).getByRole("combobox"), "roles.writer");

    await screen.findByText("readOnlyNote");
    for (const control of screen.getAllByRole("combobox")) {
      expect(control).toHaveProperty("disabled", true);
    }
  });
});
