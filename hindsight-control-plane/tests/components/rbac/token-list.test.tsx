// @vitest-environment jsdom
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import type { NewToken, Token } from "@/lib/rbac-api";
import { stubLayoutApis } from "./radix-jsdom";

vi.mock("next-intl", () => ({ useTranslations: () => (key: string) => key }));
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

import { TokenList } from "@/components/rbac/token-list";

const SECRET = "hsp_ab12_this-is-the-whole-secret";

function token(over: Partial<Token>): Token {
  return {
    id: "tk1",
    name: "laptop",
    prefix: "hsp_ab12",
    created_at: "2026-10-01T10:00:00Z",
    expires_at: null,
    last_used_at: null,
    revoked: false,
    ...over,
  };
}

function setup(tokens: Token[]) {
  const load = vi.fn().mockResolvedValue(tokens);
  const created: NewToken = {
    id: "tk9",
    name: "ci",
    prefix: "hsp_ab12",
    token: SECRET,
    expires_at: null,
  };
  const create = vi.fn().mockResolvedValue(created);
  const revoke = vi.fn().mockResolvedValue(undefined);
  render(<TokenList load={load} create={create} revoke={revoke} />);
  return { load, create, revoke };
}

describe("TokenList", () => {
  beforeAll(stubLayoutApis);
  afterEach(cleanup);

  it("lists tokens with prefix and status", async () => {
    setup([token({}), token({ id: "tk2", name: "old", revoked: true })]);
    const row = (await screen.findByText("laptop")).closest("tr") as HTMLElement;
    expect(within(row).getByText("hsp_ab12…")).toBeTruthy();
    expect(within(row).getByText("status.active")).toBeTruthy();
    const oldRow = screen.getByText("old").closest("tr") as HTMLElement;
    expect(within(oldRow).getByText("status.revoked")).toBeTruthy();
    expect(within(oldRow).queryByRole("button", { name: "revoke" })).toBeNull();
  });

  it("shows a new token once and forgets it when the dialog closes", async () => {
    const { create } = setup([]);
    await screen.findByText("empty");

    fireEvent.click(screen.getByRole("button", { name: "newToken" }));
    fireEvent.change(screen.getByLabelText("name"), { target: { value: "ci" } });
    fireEvent.click(screen.getByRole("button", { name: "create" }));

    expect(await screen.findByDisplayValue(SECRET)).toBeTruthy();
    expect(create).toHaveBeenCalledWith("ci", undefined);

    fireEvent.click(screen.getByRole("button", { name: "done" }));
    await waitFor(() => expect(screen.queryByDisplayValue(SECRET)).toBeNull());
    expect(document.body.innerHTML).not.toContain(SECRET);

    // Opening the dialog again starts a new token; the old secret is gone for good.
    fireEvent.click(screen.getByRole("button", { name: "newToken" }));
    expect(await screen.findByLabelText("name")).toBeTruthy();
    expect(document.body.innerHTML).not.toContain(SECRET);
  });

  it("revokes only after confirmation", async () => {
    const { revoke, load } = setup([token({})]);
    const row = (await screen.findByText("laptop")).closest("tr") as HTMLElement;

    fireEvent.click(within(row).getByRole("button", { name: "revoke" }));
    expect(revoke).not.toHaveBeenCalled();

    fireEvent.click(await screen.findByRole("button", { name: "revokeConfirm" }));
    await waitFor(() => expect(revoke).toHaveBeenCalledWith("tk1"));
    await waitFor(() => expect(load).toHaveBeenCalledTimes(2));
  });
});
