// @vitest-environment jsdom
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { stubLayoutApis } from "./radix-jsdom";

vi.mock("next-intl", () => ({ useTranslations: () => (key: string) => key }));
const push = vi.fn();
vi.mock("next/navigation", () => ({ useRouter: () => ({ push }) }));

import { SignedInUser } from "@/components/signed-in-user";

function signedInAs(isAdmin: boolean) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () =>
      Response.json({ user: { name: "Alice", email: "alice@x.test", is_admin: isAdmin } })
    )
  );
  render(<SignedInUser />);
}

async function openMenu() {
  fireEvent.keyDown(await screen.findByRole("button", { name: /Alice/ }), { key: "Enter" });
}

describe("SignedInUser menu", () => {
  beforeAll(stubLayoutApis);
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    push.mockReset();
  });

  it("links to My tokens, and not to Admin, for a non-admin", async () => {
    signedInAs(false);
    await openMenu();
    fireEvent.click(await screen.findByRole("menuitem", { name: "myTokens" }));
    expect(push).toHaveBeenCalledWith("/tokens");
    expect(screen.queryByRole("menuitem", { name: "admin" })).toBeNull();
  });

  it("links to Admin for an admin", async () => {
    signedInAs(true);
    await openMenu();
    fireEvent.click(await screen.findByRole("menuitem", { name: "admin" }));
    expect(push).toHaveBeenCalledWith("/admin");
  });
});
