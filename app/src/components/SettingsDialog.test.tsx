import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { api } from "../api";
import { syncScreen } from "../test/sync";
import { SettingsDialog } from "./SettingsDialog";

vi.mock("../api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      settings: vi.fn(),
      updateSettings: vi.fn(),
      changePassword: vi.fn(),
      connectBrowsers: vi.fn(),
      pairedBrowsers: vi.fn(),
      removePairedBrowser: vi.fn(),
      touchIdState: vi.fn(),
      enableTouchId: vi.fn(),
      disableTouchId: vi.fn(),
      syncScreen: vi.fn(),
      onSynced: vi.fn(),
      backups: vi.fn(),
      syncPlace: vi.fn(),
    },
  };
});

beforeEach(() => {
  vi.mocked(api.settings).mockReset().mockResolvedValue({ autoLockMinutes: 10, clipboardSeconds: 90 });
  vi.mocked(api.updateSettings).mockReset().mockImplementation(async (s) => s);
  vi.mocked(api.changePassword).mockReset().mockResolvedValue(undefined);
  vi.mocked(api.pairedBrowsers).mockReset().mockResolvedValue([{ clientId: "c1", name: "Chrome", createdAt: 1 }]);
  vi.mocked(api.connectBrowsers).mockReset().mockResolvedValue(["Chrome", "Opera"]);
  vi.mocked(api.removePairedBrowser).mockReset().mockResolvedValue(undefined);
  vi.mocked(api.touchIdState).mockReset().mockResolvedValue({ available: true, enabled: false, passwordDue: false });
  vi.mocked(api.enableTouchId).mockReset().mockResolvedValue(undefined);
  vi.mocked(api.disableTouchId).mockReset().mockResolvedValue(undefined);
  vi.mocked(api.syncScreen).mockReset().mockResolvedValue(syncScreen());
  vi.mocked(api.onSynced).mockReset().mockResolvedValue(() => {});
  vi.mocked(api.backups).mockReset().mockResolvedValue([]);
  vi.mocked(api.syncPlace).mockReset().mockResolvedValue(null);
});

type User = ReturnType<typeof userEvent.setup>;
async function openCategory(user: User, name: string) {
  const nav = screen.getByRole("tablist", { name: "Settings sections" });
  await user.click(within(nav).getByRole("tab", { name: new RegExp(`^${name}`) }));
}

test("timeouts are saved as soon as they change; there is no Save button", async () => {
  const user = userEvent.setup();
  render(<SettingsDialog onClose={vi.fn()} />);
  expect(await screen.findByLabelText("Lock after")).toHaveValue("10");
  expect(screen.queryByRole("button", { name: /Save/ })).not.toBeInTheDocument();
  await user.selectOptions(screen.getByLabelText("Lock after"), "30");
  expect(api.updateSettings).toHaveBeenLastCalledWith({ autoLockMinutes: 30, clipboardSeconds: 90 });
  expect(await screen.findByRole("status", { name: "Settings saved" })).toHaveTextContent("Saved");
  await user.selectOptions(screen.getByLabelText("Clear copied secrets after"), "30");
  expect(api.updateSettings).toHaveBeenLastCalledWith({ autoLockMinutes: 30, clipboardSeconds: 30 });
  expect(api.updateSettings).toHaveBeenCalledTimes(2);
});

test("a failed save says so; an older reply does not undo a newer choice", async () => {
  const user = userEvent.setup();
  const replies: ((s: { autoLockMinutes: number; clipboardSeconds: number }) => void)[] = [];
  vi.mocked(api.updateSettings).mockImplementation(() => new Promise((r) => replies.push(r)));
  render(<SettingsDialog onClose={vi.fn()} />);
  const lock = await screen.findByLabelText("Lock after");
  await user.selectOptions(lock, "30");
  await user.selectOptions(lock, "60");
  act(() => replies[1]({ autoLockMinutes: 60, clipboardSeconds: 90 }));
  act(() => replies[0]({ autoLockMinutes: 30, clipboardSeconds: 90 }));
  await waitFor(() => expect(lock).toHaveValue("60"));
  vi.mocked(api.updateSettings).mockRejectedValue({ kind: "other", message: "disk full" });
  await user.selectOptions(lock, "5");
  expect(await screen.findByRole("alert")).toHaveTextContent("Couldn't save settings: disk full");
});

test("changes the master password", async () => {
  const user = userEvent.setup();
  render(<SettingsDialog onClose={vi.fn()} />);
  await openCategory(user, "Security");
  const submit = screen.getByRole("button", { name: "Change password" });
  await user.type(screen.getByLabelText("Current password"), "old password 1");
  await user.type(screen.getByLabelText("New password"), "a brand new password");
  await user.type(screen.getByLabelText("Confirm new password"), "a brand new passwor");
  expect(submit).toBeDisabled();
  await user.type(screen.getByLabelText("Confirm new password"), "d");
  await user.click(submit);
  expect(api.changePassword).toHaveBeenCalledWith("old password 1", "a brand new password");
  expect(await screen.findByText("Password changed")).toBeInTheDocument();
  expect(screen.getByLabelText("Current password")).toHaveValue("");
});

test("wrong current password", async () => {
  const user = userEvent.setup();
  vi.mocked(api.changePassword).mockRejectedValue({ kind: "wrongPassword", message: "incorrect password" });
  render(<SettingsDialog onClose={vi.fn()} />);
  await openCategory(user, "Security");
  await user.type(screen.getByLabelText("Current password"), "nope nope nope");
  await user.type(screen.getByLabelText("New password"), "a brand new password");
  await user.type(screen.getByLabelText("Confirm new password"), "a brand new password");
  await user.click(screen.getByRole("button", { name: "Change password" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Current password is incorrect");
});

test("closes", async () => {
  const user = userEvent.setup();
  const onClose = vi.fn();
  render(<SettingsDialog onClose={onClose} />);
  await user.click(screen.getByRole("button", { name: "Close" }));
  expect(onClose).toHaveBeenCalled();
});

test("ignores Escape and disables Close while the password change is in flight", async () => {
  const user = userEvent.setup();
  vi.mocked(api.changePassword).mockReturnValue(new Promise(() => {}));
  const onClose = vi.fn();
  render(<SettingsDialog onClose={onClose} />);
  await openCategory(user, "Security");
  await user.type(screen.getByLabelText("Current password"), "old password 1");
  await user.type(screen.getByLabelText("New password"), "a brand new password");
  await user.type(screen.getByLabelText("Confirm new password"), "a brand new password");
  await user.click(screen.getByRole("button", { name: "Change password" }));
  expect(screen.getByRole("button", { name: "Close" })).toBeDisabled();
  act(() => {
    fireEvent.keyDown(window, { key: "Escape" });
  });
  expect(onClose).not.toHaveBeenCalled();
});

test("a settings load error does not block the password form", async () => {
  const user = userEvent.setup();
  vi.mocked(api.settings).mockRejectedValue({ kind: "other", message: "disk gone" });
  render(<SettingsDialog onClose={vi.fn()} />);
  expect(await screen.findByRole("alert")).toHaveTextContent("Couldn't load settings: disk gone");
  expect(screen.queryByLabelText("Lock after")).not.toBeInTheDocument();
  await openCategory(user, "Security");
  await user.type(screen.getByLabelText("Current password"), "old password 1");
  await user.type(screen.getByLabelText("New password"), "a brand new password");
  await user.type(screen.getByLabelText("Confirm new password"), "a brand new password");
  await user.click(screen.getByRole("button", { name: "Change password" }));
  expect(api.changePassword).toHaveBeenCalled();
});

test("shows a stored value that is not among the presets", async () => {
  vi.mocked(api.settings).mockResolvedValue({ autoLockMinutes: 15, clipboardSeconds: 90 });
  render(<SettingsDialog onClose={vi.fn()} />);
  expect(await screen.findByLabelText("Lock after")).toHaveValue("15");
});

test("status regions stay mounted", async () => {
  render(<SettingsDialog onClose={vi.fn()} />);
  await screen.findByLabelText("Lock after");
  expect(screen.getByRole("status", { name: "Settings saved" })).toBeEmptyDOMElement();
  // In a pane not shown yet, but there to be announced.
  expect(screen.getByRole("status", { name: "Password change", hidden: true })).toBeEmptyDOMElement();
});

test("switches the theme", async () => {
  const user = userEvent.setup();
  render(<SettingsDialog onClose={vi.fn()} />);
  await user.click(screen.getByRole("button", { name: "Light" }));
  expect(document.documentElement.dataset.theme).toBe("light");
  expect(screen.getByRole("button", { name: "Light" })).toHaveAttribute("aria-pressed", "true");
  await user.click(screen.getByRole("button", { name: "Dark" }));
  expect(document.documentElement.dataset.theme).toBe("dark");
  await user.click(screen.getByRole("button", { name: "Index" }));
  expect(document.documentElement.dataset.theme).toBe("index");
});

test("connects browsers and removes a paired one", async () => {
  const user = userEvent.setup();
  render(<SettingsDialog onClose={vi.fn()} />);
  await openCategory(user, "Browsers");
  expect(await screen.findByText("Chrome")).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Connect browsers" }));
  expect(
    await screen.findByText("Ready in Chrome, Opera. Load the Keyorra extension there and click Connect."),
  ).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Disconnect Chrome" }));
  expect(api.removePairedBrowser).toHaveBeenCalledWith("c1");
  await waitFor(() => expect(screen.queryByRole("button", { name: "Disconnect Chrome" })).not.toBeInTheDocument());
});

test("says so when the browsers cannot be loaded", async () => {
  vi.mocked(api.pairedBrowsers).mockRejectedValue({ kind: "other", message: "boom" });
  render(<SettingsDialog onClose={vi.fn()} initial={{ category: "browsers" }} />);
  expect(await screen.findByText("Couldn't load browsers")).toBeInTheDocument();
  expect(screen.queryByText("No browsers connected yet.")).not.toBeInTheDocument();
});

test("tells how to add Safari when its app is missing", async () => {
  vi.mocked(api.connectBrowsers).mockResolvedValue(["Chrome", "Safari: install Keyorra for Safari"]);
  const user = userEvent.setup();
  render(<SettingsDialog onClose={vi.fn()} initial={{ category: "browsers" }} />);
  await user.click(await screen.findByRole("button", { name: "Connect browsers" }));
  expect(
    await screen.findByText(
      "Ready in Chrome. Load the Keyorra extension there and click Connect. Safari: install Keyorra for Safari.",
    ),
  ).toBeInTheDocument();
});

test("turns Touch ID on and off", async () => {
  const user = userEvent.setup();
  render(<SettingsDialog onClose={vi.fn()} initial={{ category: "security" }} />);
  const box = await screen.findByLabelText("Unlock with Touch ID");
  expect(box).not.toBeChecked();
  vi.mocked(api.touchIdState).mockResolvedValue({ available: true, enabled: true, passwordDue: false });
  await user.click(box);
  expect(api.enableTouchId).toHaveBeenCalled();
  await waitFor(() => expect(box).toBeChecked());
  vi.mocked(api.touchIdState).mockResolvedValue({ available: true, enabled: false, passwordDue: false });
  await user.click(box);
  expect(api.disableTouchId).toHaveBeenCalled();
  await waitFor(() => expect(box).not.toBeChecked());
  expect(screen.getByText(/every 14 days/)).toBeInTheDocument();
});

test("Touch ID errors and Macs without it", async () => {
  const user = userEvent.setup();
  vi.mocked(api.enableTouchId).mockRejectedValue({ kind: "other", message: "Keychain: Failed" });
  const { unmount } = render(<SettingsDialog onClose={vi.fn()} initial={{ category: "security" }} />);
  await user.click(await screen.findByLabelText("Unlock with Touch ID"));
  expect(await screen.findByRole("alert")).toHaveTextContent("Keychain: Failed");
  unmount();
  vi.mocked(api.touchIdState).mockResolvedValue({ available: false, enabled: false, passwordDue: false });
  render(<SettingsDialog onClose={vi.fn()} initial={{ category: "security" }} />);
  expect(await screen.findByText("Touch ID isn't available on this Mac.")).toBeInTheDocument();
  expect(screen.queryByLabelText("Unlock with Touch ID")).not.toBeInTheDocument();
});

// ---- one wide window with categories ----

test("categories: General, Security, Sync, Browsers; one pane at a time; arrows move", async () => {
  const user = userEvent.setup();
  render(<SettingsDialog onClose={vi.fn()} />);
  const nav = screen.getByRole("tablist", { name: "Settings sections" });
  expect(nav).toHaveAttribute("aria-orientation", "vertical");
  expect(within(nav).getAllByRole("tab").map((t) => t.textContent)).toEqual(["General", "Security", "Sync", "Browsers"]);
  const general = within(nav).getByRole("tab", { name: "General" });
  expect(general).toHaveAttribute("aria-selected", "true");
  expect(screen.getByRole("tabpanel", { name: "General" })).toContainElement(await screen.findByLabelText("Lock after"));
  expect(screen.queryByRole("button", { name: "Change password" })).not.toBeInTheDocument();
  general.focus();
  await user.keyboard("{ArrowDown}");
  expect(within(nav).getByRole("tab", { name: "Security" })).toHaveFocus();
  expect(screen.getByRole("button", { name: "Change password" })).toBeInTheDocument();
  await user.keyboard("{End}");
  expect(within(nav).getByRole("tab", { name: "Browsers" })).toHaveAttribute("aria-selected", "true");
  await user.keyboard("{ArrowDown}");
  expect(general).toHaveFocus();
  // Sync lives here now: no separate window, no "Sync settings" button.
  await openCategory(user, "Sync");
  expect(await screen.findByRole("tablist", { name: "Sync sections" })).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /Sync settings/ })).not.toBeInTheDocument();
});

test("what was typed survives switching categories", async () => {
  const user = userEvent.setup();
  render(<SettingsDialog onClose={vi.fn()} initial={{ category: "security" }} />);
  await user.type(screen.getByLabelText("Current password"), "old password 1");
  await openCategory(user, "General");
  await openCategory(user, "Security");
  expect(screen.getByLabelText("Current password")).toHaveValue("old password 1");
});

test("opens on a Sync section when asked to", async () => {
  render(<SettingsDialog onClose={vi.fn()} initial={{ category: "sync", sync: "devices" }} />);
  expect(screen.getByRole("tab", { name: "Sync" })).toHaveAttribute("aria-selected", "true");
  expect(await screen.findByRole("tab", { name: "Devices" })).toHaveAttribute("aria-selected", "true");
  expect(screen.getByRole("region", { name: "Devices" })).toBeInTheDocument();
});

test("Escape closes Settings", async () => {
  const onClose = vi.fn();
  render(<SettingsDialog onClose={onClose} />);
  await screen.findByLabelText("Lock after");
  fireEvent.keyDown(window, { key: "Escape" });
  expect(onClose).toHaveBeenCalledTimes(1);
});
