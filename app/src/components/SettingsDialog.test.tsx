import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { api } from "../api";
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
});

test("loads and saves timeouts", async () => {
  const user = userEvent.setup();
  render(<SettingsDialog onClose={vi.fn()} />);
  expect(await screen.findByLabelText("Lock after")).toHaveValue("10");
  await user.selectOptions(screen.getByLabelText("Lock after"), "30");
  await user.selectOptions(screen.getByLabelText("Clear copied secrets after"), "30");
  await user.click(screen.getByRole("button", { name: "Save settings" }));
  expect(api.updateSettings).toHaveBeenCalledWith({ autoLockMinutes: 30, clipboardSeconds: 30 });
  expect(await screen.findByRole("status", { name: "Settings saved" })).toHaveTextContent("Saved");
});

test("changes the master password", async () => {
  const user = userEvent.setup();
  render(<SettingsDialog onClose={vi.fn()} />);
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
  expect(screen.getByRole("status", { name: "Password change" })).toBeEmptyDOMElement();
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
  render(<SettingsDialog onClose={vi.fn()} />);
  expect(await screen.findByText("Couldn't load browsers")).toBeInTheDocument();
  expect(screen.queryByText("No browsers connected yet.")).not.toBeInTheDocument();
});

test("tells how to add Safari when its app is missing", async () => {
  vi.mocked(api.connectBrowsers).mockResolvedValue(["Chrome", "Safari: install Keyorra for Safari"]);
  const user = userEvent.setup();
  render(<SettingsDialog onClose={vi.fn()} />);
  await user.click(await screen.findByRole("button", { name: "Connect browsers" }));
  expect(
    await screen.findByText(
      "Ready in Chrome. Load the Keyorra extension there and click Connect. Safari: install Keyorra for Safari.",
    ),
  ).toBeInTheDocument();
});

test("turns Touch ID on and off", async () => {
  const user = userEvent.setup();
  render(<SettingsDialog onClose={vi.fn()} />);
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
  const { unmount } = render(<SettingsDialog onClose={vi.fn()} />);
  await user.click(await screen.findByLabelText("Unlock with Touch ID"));
  expect(await screen.findByRole("alert")).toHaveTextContent("Keychain: Failed");
  unmount();
  vi.mocked(api.touchIdState).mockResolvedValue({ available: false, enabled: false, passwordDue: false });
  render(<SettingsDialog onClose={vi.fn()} />);
  expect(await screen.findByText("Touch ID isn't available on this Mac.")).toBeInTheDocument();
  expect(screen.queryByLabelText("Unlock with Touch ID")).not.toBeInTheDocument();
});
