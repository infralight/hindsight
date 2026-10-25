// @vitest-environment jsdom
/**
 * fork(rbac): the bank page hides what the caller may not do, and keeps doing so after
 * the Access tab changes the caller's own access.
 */
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import type { BankAccess } from "@/lib/rbac-api";
import { stubLayoutApis } from "../../components/rbac/radix-jsdom";

vi.mock("next-intl", () => ({
  useTranslations: () => Object.assign((key: string) => key, { rich: (key: string) => key }),
}));
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));
vi.mock("next/navigation", () => ({
  useParams: () => ({ bankId: "b1" }),
  useRouter: () => ({ push: vi.fn(), replace: vi.fn() }),
  useSearchParams: () => new URLSearchParams("view=profile&bankConfigTab=access"),
}));
vi.mock("@/lib/bank-context", () => ({
  useBank: () => ({ currentBank: "b1", setCurrentBank: vi.fn(), loadBanks: vi.fn() }),
}));
vi.mock("@/lib/features-context", () => ({
  useFeatures: () => ({ features: { rbac: true, observations: true } }),
}));
vi.mock("@/lib/api", () => ({ client: { getBankConfig: vi.fn() } }));

const getAccess = vi.hoisted(() => vi.fn());
vi.mock("@/lib/rbac-api", () => ({ rbac: { getAccess } }));

// The Access tab, reduced to the one thing the page relies on: it reports new access.
let reportAccess: ((access: BankAccess) => void) | undefined;
vi.mock("@/components/rbac/bank-access-view", () => ({
  BankAccessView: ({ onChange }: { onChange?: (access: BankAccess) => void }) => {
    reportAccess = onChange;
    return null;
  },
}));
const stub = () => null;
for (const [path, name] of [
  ["@/components/bank-selector", "BankSelector"],
  ["@/components/sidebar", "Sidebar"],
  ["@/components/data-view", "DataView"],
  ["@/components/documents-view", "DocumentsView"],
  ["@/components/entities-view", "EntitiesView"],
  ["@/components/knowledge-base-view", "KnowledgeBaseView"],
  ["@/components/home-view", "HomeView"],
  ["@/components/think-view", "ThinkView"],
  ["@/components/search-debug-view", "SearchDebugView"],
  ["@/components/bank-profile-view", "BankProfileView"],
  ["@/components/bank-config-view", "BankConfigView"],
  ["@/components/memory-defense-section", "MemoryDefenseSection"],
  ["@/components/bank-stats-view", "BankStatsView"],
  ["@/components/bank-operations-view", "BankOperationsView"],
  ["@/components/mental-models-view", "MentalModelsView"],
  ["@/components/webhooks-view", "WebhooksView"],
  ["@/components/audit-logs-view", "AuditLogsView"],
  ["@/components/llm-requests-view", "LLMRequestsView"],
]) {
  vi.doMock(path, () => ({ [name]: stub }));
}

const OWNER: BankAccess = {
  bank_id: "b1",
  visibility: "private",
  owner: null,
  grants: [],
  my_role: "owner",
  my_capabilities: ["delete_bank", "manage", "read", "write"],
};
const READER: BankAccess = { ...OWNER, my_role: "reader", my_capabilities: ["read"] };

async function renderPage(access: BankAccess) {
  getAccess.mockResolvedValue(access);
  const { default: BankPage } = await import("@/app/[locale]/banks/[bankId]/page");
  render(<BankPage />);
}

async function openActions() {
  fireEvent.keyDown(screen.getByRole("button", { name: /actions/ }), { key: "Enter" });
  return screen.findAllByRole("menuitem");
}

describe("bank page in rbac mode", () => {
  beforeAll(stubLayoutApis);
  afterEach(() => {
    cleanup();
    getAccess.mockReset();
  });

  it("disables the write actions and hides delete for a reader", async () => {
    await renderPage(READER);
    await screen.findByText("readOnlyBank");
    await openActions();

    for (const label of [
      "runConsolidation",
      "recoverConsolidation",
      "clearObservations",
      "resetConfiguration",
    ]) {
      expect(
        screen.getByRole("menuitem", { name: new RegExp(label) }).getAttribute("aria-disabled")
      ).toBe("true");
    }
    expect(screen.queryByRole("menuitem", { name: /deleteBank/ })).toBeNull();
  });

  it("follows the access the Access tab reports, so a transfer hides owner actions", async () => {
    await renderPage(OWNER);
    expect(await screen.findByRole("tab", { name: "webhooks" })).toBeTruthy();

    act(() => reportAccess?.(READER));

    expect(screen.queryByRole("tab", { name: "webhooks" })).toBeNull();
    expect(screen.getByText("readOnlyBank")).toBeTruthy();
    await openActions();
    expect(screen.queryByRole("menuitem", { name: /deleteBank/ })).toBeNull();
  });
});
