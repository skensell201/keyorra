import { act, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, expect, test, vi } from "vitest";
import { api } from "./api";
import { App } from "./App";

vi.mock("./api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      status: vi.fn(),
      lock: vi.fn(),
      touchIdState: vi.fn().mockResolvedValue({ available: false, enabled: false, passwordDue: false }),
      vaults: vi.fn().mockResolvedValue([]),
      items: vi.fn().mockResolvedValue([]),
      watchtower: vi.fn().mockRejectedValue({ kind: "locked", message: "locked" }),
      onLocked: vi.fn().mockResolvedValue(() => {}),
      onUnlocked: vi.fn(),
      onPairRequest: vi.fn().mockResolvedValue(() => {}),
      onItemsChanged: vi.fn().mockResolvedValue(() => {}),
    },
  };
});

let unlockedCallback: (() => void) | null = null;

beforeEach(() => {
  vi.mocked(api.status).mockReset();
  unlockedCallback = null;
  vi.mocked(api.onUnlocked)
    .mockReset()
    .mockImplementation(async (cb) => {
      unlockedCallback = cb;
      return () => {};
    });
});

test("first run shows setup", async () => {
  vi.mocked(api.status).mockResolvedValue("new");
  render(<App />);
  expect(await screen.findByRole("heading", { name: "Create your Keyorra" })).toBeInTheDocument();
});

test("a locked vault shows the unlock screen", async () => {
  vi.mocked(api.status).mockResolvedValue("locked");
  render(<App />);
  expect(await screen.findByRole("button", { name: "Unlock" })).toBeInTheDocument();
});

test("an unlocked vault shows the main window", async () => {
  vi.mocked(api.status).mockResolvedValue("unlocked");
  render(<App />);
  expect(await screen.findByRole("button", { name: "Lock" })).toBeInTheDocument();
});

test("unlocking in the quick-search window unlocks the main window too", async () => {
  vi.mocked(api.status).mockResolvedValue("locked");
  render(<App />);
  expect(await screen.findByRole("button", { name: "Unlock" })).toBeInTheDocument();
  await waitFor(() => expect(unlockedCallback).not.toBeNull());
  act(() => unlockedCallback!());
  expect(await screen.findByRole("button", { name: "Lock" })).toBeInTheDocument();
});
