/**
 * jsdom lacks the layout and pointer APIs Radix (Select, Popover) and cmdk call;
 * stub them, and drive Radix Select with the keyboard — its items select on
 * Enter, while a synthetic click is ignored for mouse pointers.
 */
import { expect } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";

export function stubLayoutApis() {
  const proto = window.HTMLElement.prototype as unknown as Record<string, unknown>;
  proto.scrollIntoView ??= () => {};
  proto.hasPointerCapture ??= () => false;
  proto.releasePointerCapture ??= () => {};
  (globalThis as Record<string, unknown>).ResizeObserver ??= class {
    observe() {}
    unobserve() {}
    disconnect() {}
  };
}

/** Opens a Radix Select trigger and picks the option whose text is `label`. */
export async function chooseOption(trigger: HTMLElement, label: string) {
  fireEvent.keyDown(trigger, { key: "Enter" });
  const option = await screen.findByRole("option", { name: label });
  fireEvent.keyDown(option, { key: "Enter" });
  // Closing hands focus back to the trigger (unless the change disabled it); a popover
  // opened before that would see the focus leave it and close again.
  await waitFor(() =>
    expect(document.activeElement === trigger || trigger.hasAttribute("disabled")).toBe(true)
  );
}
