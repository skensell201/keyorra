import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { api } from "../api";
import { syncScreen } from "../test/sync";
import { ImportDialog } from "./ImportDialog";
import { Main } from "./Main";
import { SettingsDialog } from "./SettingsDialog";
import { Setup } from "./Setup";
import { Unlock } from "./Unlock";

vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn() }));
vi.mock("../api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api")>();
  // Every command is a mock; the ones the screens read on mount get answers below.
  const api = Object.fromEntries(Object.keys(actual.api).map((name) => [name, vi.fn()]));
  return { ...actual, api };
});

beforeEach(() => {
  for (const f of Object.values(api)) vi.mocked(f as () => Promise<unknown>).mockReset().mockResolvedValue(undefined);
  for (const [name, f] of Object.entries(api)) {
    // Event subscriptions resolve to an unlisten function.
    if (name.startsWith("on")) vi.mocked(f as () => Promise<unknown>).mockResolvedValue(() => {});
  }
  vi.mocked(api.vaults).mockResolvedValue([{ id: "v1", name: "Personal", itemCount: 0 }]);
  vi.mocked(api.items).mockResolvedValue([]);
  vi.mocked(api.watchtowerCount).mockResolvedValue(0);
  vi.mocked(api.settings).mockResolvedValue({ autoLockMinutes: 10, clipboardSeconds: 90 });
  vi.mocked(api.pairedBrowsers).mockResolvedValue([{ clientId: "c1", name: "Chrome", createdAt: 1 }]);
  vi.mocked(api.touchIdState).mockResolvedValue({ available: true, enabled: false, passwordDue: false });
  vi.mocked(api.syncPlace).mockResolvedValue({ path: "/Users/a/Keyorra", kind: "local", warning: null });
  vi.mocked(api.backups).mockResolvedValue([]);
  vi.mocked(api.syncScreen).mockResolvedValue(syncScreen());
});

/** Commands read as commands: no button, menu item or link ends in "…" or "...". */
function expectNoEllipsis() {
  const controls = [
    ...screen.queryAllByRole("button"),
    ...screen.queryAllByRole("menuitem"),
    ...screen.queryAllByRole("link"),
    ...screen.queryAllByRole("tab"),
  ];
  expect(controls.length).toBeGreaterThan(0);
  for (const control of controls) {
    for (const text of [control.textContent ?? "", control.getAttribute("aria-label") ?? ""]) {
      expect(text.trim(), `"${text}"`).not.toMatch(/(…|\.\.\.)$/);
    }
  }
}

test("the main window", async () => {
  render(<Main onLock={vi.fn()} />);
  await screen.findByRole("button", { name: "Settings" });
  expectNoEllipsis();
});

test("Settings, every category and every Sync section, with sync on and off", async () => {
  const user = userEvent.setup();
  const { unmount } = render(<SettingsDialog onClose={vi.fn()} />);
  await screen.findByLabelText("Lock after");
  for (const category of ["General", "Security", "Browsers", "Sync"]) {
    const nav = screen.getByRole("tablist", { name: "Settings sections" });
    await user.click(within(nav).getByRole("tab", { name: new RegExp(`^${category}`) }));
    expectNoEllipsis();
  }
  for (const name of ["Overview", "Devices", "Safety", "Advanced"]) {
    const sections = await screen.findByRole("tablist", { name: "Sync sections" });
    await user.click(within(sections).getByRole("tab", { name: new RegExp(`^${name}`) }));
    expectNoEllipsis();
  }
  unmount();
  vi.mocked(api.syncScreen).mockResolvedValue(syncScreen({ enabled: false, status: null }));
  render(<SettingsDialog onClose={vi.fn()} initial={{ category: "sync" }} />);
  await user.click(await screen.findByRole("button", { name: "Join a synced account" }));
  expectNoEllipsis();
});

test("first run, unlock and import", async () => {
  const { unmount } = render(<Setup onDone={vi.fn()} />);
  expectNoEllipsis();
  unmount();
  const second = render(<Unlock onUnlocked={vi.fn()} onStartOver={vi.fn()} />);
  await waitFor(() => expect(api.touchIdState).toHaveBeenCalled());
  expectNoEllipsis();
  second.unmount();
  render(<ImportDialog onClose={vi.fn()} onImported={vi.fn()} />);
  expectNoEllipsis();
});
