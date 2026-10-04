import { act, fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { api } from "../api";
import { SettingsDialog } from "./SettingsDialog";

vi.mock("../api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api")>();
  return {
    ...actual,
    api: { ...actual.api, settings: vi.fn(), updateSettings: vi.fn(), changePassword: vi.fn() },
  };
});

beforeEach(() => {
  vi.mocked(api.settings).mockReset().mockResolvedValue({ autoLockMinutes: 10, clipboardSeconds: 90 });
  vi.mocked(api.updateSettings).mockReset().mockImplementation(async (s) => s);
  vi.mocked(api.changePassword).mockReset().mockResolvedValue(undefined);
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
  await user.click(screen.getByRole("button", { name: "Index" }));
  expect(document.documentElement.dataset.theme).toBe("index");
  expect(screen.getByRole("button", { name: "Index" })).toHaveAttribute("aria-pressed", "true");
  await user.click(screen.getByRole("button", { name: "Doppler" }));
  expect(document.documentElement.dataset.theme).toBe("doppler");
});
