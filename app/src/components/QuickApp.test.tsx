import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { api } from "../api";
import { QuickApp } from "./QuickApp";

vi.mock("../api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      status: vi.fn(),
      items: vi.fn(),
      touchIdState: vi.fn().mockResolvedValue({ available: false, enabled: false, passwordDue: false }),
      quickHide: vi.fn(),
      onLocked: vi.fn(),
      onUnlocked: vi.fn(),
      onQuickOpen: vi.fn(),
    },
  };
});

const callbacks: Record<string, () => void> = {};

beforeEach(() => {
  vi.mocked(api.status).mockReset().mockResolvedValue("unlocked");
  vi.mocked(api.items).mockReset().mockResolvedValue([]);
  vi.mocked(api.quickHide).mockReset().mockResolvedValue(undefined);
  for (const name of ["onLocked", "onUnlocked", "onQuickOpen"] as const) {
    vi.mocked(api[name])
      .mockReset()
      .mockImplementation(async (cb: () => void) => {
        callbacks[name] = cb;
        return () => {};
      });
  }
});

test("unlocked shows the search box; Escape hides the window", async () => {
  const user = userEvent.setup();
  render(<QuickApp />);
  expect(await screen.findByLabelText("Quick search")).toHaveFocus();
  await user.keyboard("{Escape}");
  expect(api.quickHide).toHaveBeenCalled();
});

test("locked shows the unlock form and follows lock events", async () => {
  vi.mocked(api.status).mockResolvedValue("locked");
  render(<QuickApp />);
  expect(await screen.findByLabelText("Master password")).toBeInTheDocument();
  await waitFor(() => expect(callbacks.onUnlocked).toBeDefined());
  act(() => callbacks.onUnlocked());
  expect(await screen.findByLabelText("Quick search")).toBeInTheDocument();
  act(() => callbacks.onLocked());
  expect(await screen.findByLabelText("Master password")).toBeInTheDocument();
});

test("opening the window again starts with an empty search", async () => {
  const user = userEvent.setup();
  render(<QuickApp />);
  await user.type(await screen.findByLabelText("Quick search"), "git");
  act(() => callbacks.onQuickOpen());
  await waitFor(() => expect(screen.getByLabelText("Quick search")).toHaveValue(""));
  expect(api.status).toHaveBeenCalledTimes(2);
});
