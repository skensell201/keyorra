import { render, screen } from "@testing-library/react";
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
      vaults: vi.fn().mockResolvedValue([]),
      items: vi.fn().mockResolvedValue([]),
      onLocked: vi.fn().mockResolvedValue(() => {}),
      onPairRequest: vi.fn().mockResolvedValue(() => {}),
      onItemsChanged: vi.fn().mockResolvedValue(() => {}),
    },
  };
});

beforeEach(() => {
  vi.mocked(api.status).mockReset();
});

test("first run shows setup", async () => {
  vi.mocked(api.status).mockResolvedValue("new");
  render(<App />);
  expect(await screen.findByRole("heading", { name: "Create your Keepsake" })).toBeInTheDocument();
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
