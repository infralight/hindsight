// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";

let features: { rbac: boolean } | null = { rbac: false };
vi.mock("@/lib/features-context", () => ({ useFeatures: () => ({ features }) }));

const getAccess = vi.fn();
vi.mock("@/lib/rbac-api", () => ({ rbac: { getAccess: (id: string) => getAccess(id) } }));

import { useBankAccess } from "@/lib/use-bank-access";

describe("useBankAccess", () => {
  afterEach(() => getAccess.mockReset());

  it("can() is true for everything outside rbac mode without fetching", () => {
    features = { rbac: false };
    const { result } = renderHook(() => useBankAccess("b1"));
    expect(result.current.can("manage")).toBe(true);
    expect(result.current.can("delete_bank")).toBe(true);
    expect(getAccess).not.toHaveBeenCalled();
  });

  it('can("delete_bank") is false for a writer on a public bank', async () => {
    features = { rbac: true };
    getAccess.mockResolvedValue({
      bank_id: "b1",
      visibility: "public",
      owner: null,
      grants: [],
      my_role: "writer",
      my_capabilities: ["read", "write"],
    });
    const { result } = renderHook(() => useBankAccess("b1"));

    await waitFor(() => expect(result.current.access).not.toBeNull());
    expect(getAccess).toHaveBeenCalledWith("b1");
    expect(result.current.can("write")).toBe(true);
    expect(result.current.can("delete_bank")).toBe(false);
    expect(result.current.can("manage")).toBe(false);
  });

  it("grants nothing until it knows the caller's access", () => {
    features = { rbac: true };
    getAccess.mockReturnValue(new Promise(() => {}));
    const { result } = renderHook(() => useBankAccess("b1"));
    expect(result.current.can("read")).toBe(false);
  });
});
