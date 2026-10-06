import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { open } from "@tauri-apps/plugin-dialog";
import { beforeEach, expect, test, vi } from "vitest";
import { api } from "../api";
import { syncScreen } from "../test/sync";
import { SyncDialog } from "./SyncDialog";

vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn() }));
vi.mock("../api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      syncScreen: vi.fn(),
      syncNow: vi.fn(),
      onSynced: vi.fn(),
      syncPlace: vi.fn(),
      setSyncPlace: vi.fn(),
      enableSync: vi.fn(),
      joinSync: vi.fn(),
      disableSync: vi.fn(),
      syncAlarmAction: vi.fn(),
      removeSyncDevice: vi.fn(),
      verifySync: vi.fn(),
      syncFolderFiles: vi.fn(),
      emergencyKit: vi.fn(),
      startNewSyncAccount: vi.fn(),
      backups: vi.fn(),
      deleteBackup: vi.fn(),
      approveDevice: vi.fn(),
      copySetupCode: vi.fn(),
    },
  };
});

const off = syncScreen({ enabled: false, running: false, status: null, log: [] });
const kit = { accountId: "0101".repeat(8), secretKey: "A3KX-ABCDE-FGHJK", location: "/sync/Keyorra/0101" };

beforeEach(() => {
  vi.mocked(api.syncScreen).mockReset().mockResolvedValue(syncScreen());
  vi.mocked(api.onSynced).mockReset().mockResolvedValue(() => {});
  vi.mocked(api.syncPlace).mockReset().mockResolvedValue({
    path: "/Users/a/Library/Mobile Documents/com~apple~CloudDocs/Keyorra",
    kind: "icloud",
    warning: null,
  });
  vi.mocked(api.backups).mockReset().mockResolvedValue([]);
  for (const f of [
    api.syncNow, api.setSyncPlace, api.enableSync, api.joinSync, api.disableSync, api.syncAlarmAction,
    api.removeSyncDevice, api.verifySync, api.syncFolderFiles, api.emergencyKit, api.startNewSyncAccount,
    api.deleteBackup, api.approveDevice, api.copySetupCode,
  ]) {
    vi.mocked(f).mockReset();
  }
});

test("turning sync on shows the Emergency Kit to print", async () => {
  const user = userEvent.setup();
  vi.mocked(api.syncScreen).mockResolvedValue(off);
  vi.mocked(api.enableSync).mockResolvedValue(kit);
  render(<SyncDialog onClose={vi.fn()} />);
  expect(await screen.findByText(/CloudDocs\/Keyorra/)).toBeInTheDocument();
  await user.type(screen.getByLabelText("Master password"), "correct horse battery");
  await user.click(screen.getByRole("button", { name: "Turn on sync" }));
  expect(api.enableSync).toHaveBeenCalledWith("correct horse battery");
  const sheet = await screen.findByRole("region", { name: "Emergency Kit" });
  expect(within(sheet).getByTestId("secret-key")).toHaveTextContent("A3KX-ABCDE-FGHJK");
  // Review A3 I5: the kit shown right after turning on says where the account lives.
  expect(within(sheet).getByText("/sync/Keyorra/0101")).toBeInTheDocument();
  const print = vi.spyOn(window, "print").mockImplementation(() => {});
  await user.click(within(sheet).getByRole("button", { name: "Print" }));
  expect(print).toHaveBeenCalled();
});

test("another folder can be chosen, with its warning", async () => {
  const user = userEvent.setup();
  vi.mocked(api.syncScreen).mockResolvedValue(off);
  vi.mocked(open).mockResolvedValue("/Users/a/Library/CloudStorage/Dropbox");
  vi.mocked(api.setSyncPlace).mockResolvedValue({
    path: "/Users/a/Library/CloudStorage/Dropbox/Keyorra",
    kind: "cloudStorage",
    warning: "Set this folder to stay downloaded",
  });
  render(<SyncDialog onClose={vi.fn()} />);
  await user.click(await screen.findByRole("button", { name: "Choose another folder…" }));
  expect(api.setSyncPlace).toHaveBeenCalledWith("/Users/a/Library/CloudStorage/Dropbox");
  expect(await screen.findByText("Set this folder to stay downloaded")).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Use iCloud Drive" }));
  expect(api.setSyncPlace).toHaveBeenLastCalledWith(null);
});

test("an alarm offers its actions", async () => {
  const user = userEvent.setup();
  vi.mocked(api.syncScreen).mockResolvedValue(
    syncScreen({
      alarms: [
        {
          id: "a1",
          kind: "rollback",
          title: "Changes of Laptop went missing from the sync folder",
          explanation: "The folder holds fewer of that device's changes.",
          actions: ["restore", "accept"],
        },
      ],
    }),
  );
  vi.mocked(api.syncAlarmAction).mockResolvedValue(undefined);
  render(<SyncDialog onClose={vi.fn()} />);
  const alarms = await screen.findByRole("region", { name: "Alarms" });
  expect(within(alarms).getByText(/went missing/)).toBeInTheDocument();
  await user.click(within(alarms).getByRole("button", { name: "Restore from this Mac" }));
  // Review A3 I6: asked first, the safe choice focused.
  const confirm = screen.getByRole("alertdialog");
  expect(within(confirm).getByText(/writes the changes that went missing back/)).toBeInTheDocument();
  expect(within(confirm).getByRole("button", { name: "Cancel" })).toHaveFocus();
  expect(api.syncAlarmAction).not.toHaveBeenCalled();
  await user.click(within(confirm).getByRole("button", { name: "Restore from this Mac" }));
  expect(api.syncAlarmAction).toHaveBeenCalledWith("a1", "restore");
});

test("the main Mac removes a device after confirming", async () => {
  const user = userEvent.setup();
  vi.mocked(api.removeSyncDevice).mockResolvedValue(undefined);
  render(<SyncDialog onClose={vi.fn()} />);
  const devices = await screen.findByRole("region", { name: "Devices" });
  await user.click(within(devices).getByRole("button", { name: "Remove" }));
  await user.click(screen.getByRole("button", { name: "Remove device" }));
  expect(api.removeSyncDevice).toHaveBeenCalledWith("d1");
});

test("a device waiting for approval is reviewed with its code", async () => {
  const user = userEvent.setup();
  const s = syncScreen();
  s.status!.devices.push({ id: "d2", name: "New Mac", approved: false, main: false, thisDevice: false, removed: false });
  vi.mocked(api.syncScreen).mockResolvedValue(s);
  vi.mocked(api.approveDevice).mockResolvedValue(undefined);
  render(<SyncDialog onClose={vi.fn()} />);
  const approvals = await screen.findByRole("region", { name: "Approvals" });
  await user.click(within(approvals).getByRole("button", { name: "Review" }));
  const approve = screen.getByRole("button", { name: "Approve" });
  await user.type(screen.getByLabelText("Code shown on New Mac"), "0a1b-2c3d-4e5");
  expect(approve).toBeDisabled();
  await user.type(screen.getByLabelText("Code shown on New Mac"), "f");
  await user.click(approve);
  expect(api.approveDevice).toHaveBeenCalledWith("d2", "0a1b-2c3d-4e5f");
});

test("the Emergency Kit asks for the password when it was not entered lately", async () => {
  const user = userEvent.setup();
  vi.mocked(api.emergencyKit)
    .mockRejectedValueOnce({ kind: "passwordRequired", message: "Enter your master password" })
    .mockResolvedValueOnce(kit);
  render(<SyncDialog onClose={vi.fn()} />);
  await user.click(await screen.findByRole("button", { name: "Emergency Kit…" }));
  await user.type(await screen.findByLabelText("Master password for the Emergency Kit"), "correct horse battery");
  await user.click(screen.getByRole("button", { name: "Show" }));
  expect(api.emergencyKit).toHaveBeenLastCalledWith("correct horse battery");
  expect(await screen.findByTestId("secret-key")).toHaveTextContent("A3KX");
});

test("verify, folder files and the log", async () => {
  const user = userEvent.setup();
  vi.mocked(api.verifySync).mockResolvedValue({
    items: 12,
    damaged: 0,
    attachments: 2,
    damagedAttachments: 0,
    differing: [],
    missing: 0,
  });
  vi.mocked(api.syncFolderFiles).mockResolvedValue([
    { path: "streams/0101/0000000000000001.seg", size: 2048, counted: true },
    { path: "streams/0101/x (1).seg", size: 10, counted: false },
  ]);
  render(<SyncDialog onClose={vi.fn()} />);
  await user.click(await screen.findByRole("button", { name: "Verify everything" }));
  expect(await screen.findByRole("status", { name: "Verify" })).toHaveTextContent("12 item(s) and 2 attachment(s) checked. Everything matches.");
  await user.click(screen.getByRole("button", { name: "What the folder sees" }));
  const table = await screen.findByRole("table", { name: "Folder files" });
  expect(within(table).getByText("2.0 KB")).toBeInTheDocument();
  expect(within(table).getByText("unknown, ignored")).toBeInTheDocument();
  expect(screen.getByText(/Received 2 change\(s\) from Laptop/)).toBeInTheDocument();
});

test("turning sync off and starting a new account", async () => {
  const user = userEvent.setup();
  vi.mocked(api.disableSync).mockResolvedValue(undefined);
  vi.mocked(api.startNewSyncAccount).mockResolvedValue(kit);
  render(<SyncDialog onClose={vi.fn()} />);
  await user.click(await screen.findByRole("button", { name: "Turn off sync" }));
  await user.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: "Turn off sync" }));
  expect(api.disableSync).toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Start a new account…" }));
  const dialog = screen.getByRole("alertdialog");
  expect(within(dialog).getByText(/a device was stolen/)).toBeInTheDocument();
  await user.type(within(dialog).getByLabelText("Master password"), "correct horse battery");
  await user.click(within(dialog).getByRole("button", { name: "Start a new account" }));
  expect(api.startNewSyncAccount).toHaveBeenCalledWith("correct horse battery");
  expect(await screen.findByRole("region", { name: "Emergency Kit" })).toBeInTheDocument();
});

test("backup copies can be deleted", async () => {
  const user = userEvent.setup();
  vi.mocked(api.backups).mockResolvedValue([
    { name: "keyorra.db.bak-v1", size: 4096, modified: 1_790_000_000, kind: "migration" },
  ]);
  vi.mocked(api.deleteBackup).mockResolvedValue(undefined);
  render(<SyncDialog onClose={vi.fn()} />);
  const backups = await screen.findByRole("region", { name: "Backups" });
  expect(within(backups).getByText(/Before an upgrade/)).toBeInTheDocument();
  await user.click(within(backups).getByRole("button", { name: "Delete" }));
  await user.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: "Delete" }));
  await waitFor(() => expect(api.deleteBackup).toHaveBeenCalledWith("keyorra.db.bak-v1"));
});

// ---- review of A3 ----

function alarm(actions: ("accept" | "restore" | "remove" | "leave")[]) {
  return syncScreen({
    alarms: [{ id: "a1", kind: "fork", title: "Two different histories of Laptop", explanation: "x", actions }],
  });
}

test("review A3 I6: removing and leaving from an alarm are confirmed; Cancel does nothing", async () => {
  const user = userEvent.setup();
  vi.mocked(api.syncScreen).mockResolvedValue(alarm(["remove", "leave", "accept"]));
  vi.mocked(api.syncAlarmAction).mockResolvedValue(undefined);
  render(<SyncDialog onClose={vi.fn()} />);
  const alarms = await screen.findByRole("region", { name: "Alarms" });
  await user.click(within(alarms).getByRole("button", { name: "Remove device" }));
  expect(within(screen.getByRole("alertdialog")).getByText(/can no longer read/)).toBeInTheDocument();
  await user.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: "Cancel" }));
  expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
  await user.click(within(alarms).getByRole("button", { name: "Continue as a new device" }));
  const leave = screen.getByRole("alertdialog");
  expect(within(leave).getByText(/approve it again/)).toBeInTheDocument();
  await user.click(within(leave).getByRole("button", { name: "Continue as a new device" }));
  expect(api.syncAlarmAction).toHaveBeenCalledTimes(1);
  expect(api.syncAlarmAction).toHaveBeenCalledWith("a1", "leave");
  // Accepting changes nothing in the account: done at once.
  await user.click(within(alarms).getByRole("button", { name: "Accept" }));
  expect(api.syncAlarmAction).toHaveBeenLastCalledWith("a1", "accept");
});

test("review A3 I7: Escape while starting a new account does not close Sync", async () => {
  const user = userEvent.setup();
  const onClose = vi.fn();
  render(<SyncDialog onClose={onClose} />);
  await user.click(await screen.findByRole("button", { name: "Start a new account…" }));
  await user.type(within(screen.getByRole("alertdialog")).getByLabelText("Master password"), "correct horse");
  fireEvent.keyDown(window, { key: "Escape" });
  expect(onClose).not.toHaveBeenCalled();
  expect(screen.getByRole("alertdialog")).toBeInTheDocument();
  expect(within(screen.getByRole("alertdialog")).getByLabelText("Master password")).toHaveValue("correct horse");
  await user.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: "Cancel" }));
  fireEvent.keyDown(window, { key: "Escape" });
  expect(onClose).toHaveBeenCalledTimes(1);
});

test("review A3 I7: Escape in a confirmation closes only the confirmation", async () => {
  const user = userEvent.setup();
  const onClose = vi.fn();
  render(<SyncDialog onClose={onClose} />);
  await user.click(await screen.findByRole("button", { name: "Turn off sync" }));
  fireEvent.keyDown(window, { key: "Escape" });
  expect(onClose).not.toHaveBeenCalled();
  await waitFor(() => expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument());
});

test("review A3 I7: Escape does not close Sync while the kit is shown or a command runs", async () => {
  const user = userEvent.setup();
  const onClose = vi.fn();
  vi.mocked(api.emergencyKit).mockResolvedValue(kit);
  let finish: (r: Awaited<ReturnType<typeof api.verifySync>>) => void = () => {};
  vi.mocked(api.verifySync).mockReturnValue(new Promise((r) => (finish = r)));
  render(<SyncDialog onClose={onClose} />);
  await user.click(await screen.findByRole("button", { name: "Verify everything" }));
  fireEvent.keyDown(window, { key: "Escape" });
  expect(onClose).not.toHaveBeenCalled();
  // Minor: the other tools wait meanwhile.
  for (const name of ["Emergency Kit…", "Verify everything", "What the folder sees", "Remove"]) {
    expect(screen.getByRole("button", { name })).toBeDisabled();
  }
  finish({ items: 1, damaged: 0, attachments: 0, damagedAttachments: 0, differing: [], missing: 0 });
  await waitFor(() => expect(screen.getByRole("button", { name: "Emergency Kit…" })).toBeEnabled());
  await user.click(screen.getByRole("button", { name: "Emergency Kit…" }));
  await screen.findByRole("region", { name: "Emergency Kit" });
  fireEvent.keyDown(window, { key: "Escape" });
  expect(onClose).not.toHaveBeenCalled();
});

test("review A3: the folder table has headers; a wrong kit password is cleared", async () => {
  const user = userEvent.setup();
  vi.mocked(api.syncFolderFiles).mockResolvedValue([{ path: "header", size: 10, counted: true }]);
  vi.mocked(api.emergencyKit)
    .mockRejectedValueOnce({ kind: "passwordRequired", message: "Enter your master password" })
    .mockRejectedValueOnce({ kind: "wrongPassword", message: "Wrong" });
  render(<SyncDialog onClose={vi.fn()} />);
  await user.click(await screen.findByRole("button", { name: "What the folder sees" }));
  const table = await screen.findByRole("table", { name: "Folder files" });
  expect(within(table).getAllByRole("columnheader").map((h) => h.textContent)).toEqual(["Name", "Size", "Status"]);
  await user.click(screen.getByRole("button", { name: "Emergency Kit…" }));
  const input = await screen.findByLabelText("Master password for the Emergency Kit");
  await user.type(input, "wrong password");
  await user.click(screen.getByRole("button", { name: "Show" }));
  expect(await screen.findByText("The master password is wrong")).toBeInTheDocument();
  expect(screen.getByLabelText("Master password for the Emergency Kit")).toHaveValue("");
  await user.click(screen.getByRole("button", { name: "Cancel" }));
  expect(screen.queryByLabelText("Master password for the Emergency Kit")).not.toBeInTheDocument();
});
