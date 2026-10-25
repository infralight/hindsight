// @vitest-environment jsdom
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { stubLayoutApis } from "./radix-jsdom";

vi.mock("next-intl", () => ({ useTranslations: () => (key: string) => key }));

const rbac = vi.hoisted(() => ({
  listTeams: vi.fn(),
  createTeam: vi.fn(),
  renameTeam: vi.fn(),
  deleteTeam: vi.fn(),
  addMember: vi.fn(),
  removeMember: vi.fn(),
  directory: vi.fn(),
}));
vi.mock("@/lib/rbac-api", () => ({ rbac }));

import { AdminTeams } from "@/components/rbac/admin-teams";

const BOB = { id: "u-bob", kind: "user", email: "bob@x.test", name: "Bob", is_admin: false };
const PLATFORM = { id: "t1", name: "Platform", members: [] };

describe("AdminTeams", () => {
  beforeAll(stubLayoutApis);
  afterEach(() => {
    cleanup();
    Object.values(rbac).forEach((fn) => fn.mockReset());
  });

  it("adding a member calls addMember with the picked principal", async () => {
    rbac.listTeams.mockResolvedValue([PLATFORM]);
    rbac.directory.mockResolvedValue({ principals: [BOB], teams: [{ id: "t2", name: "Other" }] });
    rbac.addMember.mockResolvedValue(undefined);
    render(<AdminTeams />);
    await screen.findByText("Platform");

    fireEvent.click(screen.getByRole("button", { name: "addMember" }));
    fireEvent.click(await screen.findByText("Bob"));

    await waitFor(() => expect(rbac.addMember).toHaveBeenCalledWith("t1", "u-bob"));
    // Teams are not members of teams.
    expect(screen.queryByText("Other")).toBeNull();
    await waitFor(() => expect(rbac.listTeams).toHaveBeenCalledTimes(2));
  });

  it("deleting a team asks first", async () => {
    rbac.listTeams.mockResolvedValue([PLATFORM]);
    rbac.deleteTeam.mockResolvedValue(undefined);
    render(<AdminTeams />);
    await screen.findByText("Platform");

    fireEvent.click(screen.getByRole("button", { name: "deleteTeam" }));
    expect(rbac.deleteTeam).not.toHaveBeenCalled();

    fireEvent.click(await screen.findByRole("button", { name: "deleteTeamConfirm" }));
    await waitFor(() => expect(rbac.deleteTeam).toHaveBeenCalledWith("t1"));
  });
});
