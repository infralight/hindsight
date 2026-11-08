// @vitest-environment jsdom
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { stubLayoutApis } from "./radix-jsdom";

vi.mock("next-intl", () => ({ useTranslations: () => (key: string) => key }));

const directory = vi.fn();
vi.mock("@/lib/rbac-api", () => ({ rbac: { directory: (q: string) => directory(q) } }));

import { DirectoryPicker } from "@/components/rbac/directory-picker";

const BOB = { id: "u-bob", kind: "user", email: "bob@x.test", name: "Bob", is_admin: false };
const CAROL = {
  id: "u-carol",
  kind: "user",
  email: "carol@x.test",
  name: "Carol",
  is_admin: false,
};
const PLATFORM = { id: "t-platform", name: "Platform" };

function open(exclude = new Set<string>(), onPick = vi.fn()) {
  render(
    <DirectoryPicker
      kinds={["principal", "team"]}
      exclude={exclude}
      onPick={onPick}
      placeholder="Add people or teams"
    />
  );
  fireEvent.click(screen.getByRole("button", { name: "Add people or teams" }));
  return onPick;
}

describe("DirectoryPicker", () => {
  beforeAll(stubLayoutApis);
  afterEach(() => {
    cleanup();
    directory.mockReset();
  });

  it("debounces the directory search", async () => {
    directory.mockResolvedValue({ principals: [CAROL], teams: [] });
    open();
    const input = screen.getByPlaceholderText("search");
    fireEvent.change(input, { target: { value: "c" } });
    fireEvent.change(input, { target: { value: "ca" } });
    fireEvent.change(input, { target: { value: "car" } });

    await screen.findByText("Carol");
    expect(directory).toHaveBeenCalledTimes(1);
    expect(directory).toHaveBeenCalledWith("car");
  });

  it("does not search again when the parent re-renders", async () => {
    directory.mockResolvedValue({ principals: [CAROL], teams: [] });
    const picker = () => (
      <DirectoryPicker
        kinds={["principal"]}
        exclude={new Set()}
        onPick={vi.fn()}
        placeholder="Add"
      />
    );
    const { rerender } = render(picker());
    fireEvent.click(screen.getByRole("button", { name: "Add" }));
    await screen.findByText("Carol");

    rerender(picker());
    await new Promise((resolve) => setTimeout(resolve, 300));
    expect(directory).toHaveBeenCalledTimes(1);
  });

  it("shows an empty state when nothing matches", async () => {
    directory.mockResolvedValue({ principals: [], teams: [] });
    open();
    expect(await screen.findByText("noMatches")).toBeTruthy();
  });

  it("does not offer principals already in exclude", async () => {
    directory.mockResolvedValue({ principals: [BOB, CAROL], teams: [PLATFORM] });
    open(new Set(["u-bob"]));
    await screen.findByText("Carol");
    expect(screen.queryByText("Bob")).toBeNull();
    expect(screen.getByText("Platform")).toBeTruthy();
  });

  it("hands the picked team to onPick", async () => {
    directory.mockResolvedValue({ principals: [], teams: [PLATFORM] });
    const onPick = open();
    fireEvent.click(await screen.findByText("Platform"));
    await waitFor(() =>
      expect(onPick).toHaveBeenCalledWith({ type: "team", id: "t-platform", name: "Platform" })
    );
  });
});
