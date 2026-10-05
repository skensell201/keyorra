import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { api, type ItemSummary, type PairingRequest } from "../api";
import { loginItem } from "../test/fixtures";
import { Main } from "./Main";

vi.mock("../api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      vaults: vi.fn(),
      items: vi.fn(),
      item: vi.fn(),
      totp: vi.fn(),
      newItem: vi.fn(),
      saveItem: vi.fn(),
      createVault: vi.fn(),
      renameVault: vi.fn(),
      deleteVault: vi.fn(),
      deletedItems: vi.fn(),
      restoreItem: vi.fn(),
      settings: vi.fn(),
      onPairRequest: vi.fn(),
      onItemsChanged: vi.fn(),
    },
  };
});

let pairCallback: ((r: PairingRequest) => void) | null = null;
let changedCallback: (() => void) | null = null;

const github: ItemSummary = {
  id: "i1", vaultId: "v1", kind: "login", title: "GitHub", subtitle: "ivan",
  favorite: false, hasTotp: true, updatedAt: 2, damaged: false,
};

beforeEach(() => {
  pairCallback = null;
  changedCallback = null;
  vi.mocked(api.onItemsChanged)
    .mockReset()
    .mockImplementation(async (cb) => {
      changedCallback = cb;
      return () => {};
    });
  vi.mocked(api.onPairRequest)
    .mockReset()
    .mockImplementation(async (cb) => {
      pairCallback = cb;
      return () => {};
    });
  vi.mocked(api.vaults).mockReset().mockResolvedValue([
    { id: "v1", name: "Personal", itemCount: 1 },
    { id: "v2", name: "Work", itemCount: 0 },
  ]);
  vi.mocked(api.items).mockReset().mockResolvedValue([github]);
  vi.mocked(api.item).mockReset().mockResolvedValue(loginItem());
  vi.mocked(api.totp).mockReset().mockResolvedValue(null);
  vi.mocked(api.newItem).mockReset().mockResolvedValue(loginItem({ id: "new", title: "" }));
  vi.mocked(api.saveItem).mockReset().mockImplementation(async (item) => item);
  vi.mocked(api.createVault).mockReset().mockResolvedValue({ id: "v3", name: "Home", itemCount: 0 });
  vi.mocked(api.renameVault).mockReset().mockResolvedValue({ id: "v2", name: "Office", itemCount: 0 });
  vi.mocked(api.deleteVault).mockReset().mockResolvedValue(undefined);
  vi.mocked(api.deletedItems).mockReset().mockResolvedValue([{ ...github, id: "d1", title: "Old forum" }]);
  vi.mocked(api.restoreItem).mockReset().mockResolvedValue(undefined);
  vi.mocked(api.settings).mockReset().mockResolvedValue({ autoLockMinutes: 10, clipboardSeconds: 90 });
});

const lastFilter = () => vi.mocked(api.items).mock.lastCall![0];

test("loads everything, filters by vault and search", async () => {
  const user = userEvent.setup();
  render(<Main onLock={vi.fn()} />);
  expect(await screen.findByText("GitHub")).toBeInTheDocument();
  expect(lastFilter()).toEqual({ query: "", vaultId: null, favorites: false });

  await user.click(screen.getByRole("button", { name: /Work/ }));
  await waitFor(() => expect(lastFilter()).toEqual({ query: "", vaultId: "v2", favorites: false }));
  await user.type(screen.getByLabelText("Search"), "git");
  await waitFor(() => expect(lastFilter().query).toBe("git"));
});

test("selecting an item opens its details and Edit opens the editor", async () => {
  const user = userEvent.setup();
  render(<Main onLock={vi.fn()} />);
  await user.click(await screen.findByText("GitHub"));
  expect(await screen.findByRole("heading", { name: "GitHub" })).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Edit" }));
  expect(screen.getByLabelText("Title")).toHaveValue("GitHub");
});

test("a new item is created in the selected vault, saved and shown", async () => {
  const user = userEvent.setup();
  render(<Main onLock={vi.fn()} />);
  await user.click(await screen.findByRole("button", { name: /Work/ }));
  await user.click(screen.getByRole("button", { name: "+ New" }));
  await user.click(screen.getByRole("menuitem", { name: "Login" }));
  expect(api.newItem).toHaveBeenCalledWith("v2", "login");
  await user.type(await screen.findByLabelText("Title"), "Jira");
  await user.click(screen.getByRole("button", { name: "Save" }));
  await waitFor(() => expect(api.saveItem).toHaveBeenCalled());
  await waitFor(() => expect(api.vaults).toHaveBeenCalledTimes(2));
});

test("new vault and lock", async () => {
  const user = userEvent.setup();
  const onLock = vi.fn();
  render(<Main onLock={onLock} />);
  await user.click(await screen.findByRole("button", { name: "+ New vault" }));
  await user.type(screen.getByLabelText("Vault name"), "Home{Enter}");
  expect(api.createVault).toHaveBeenCalledWith("Home");
  await user.click(screen.getByRole("button", { name: "Lock" }));
  expect(onLock).toHaveBeenCalled();
});

test("import opens the dialog", async () => {
  const user = userEvent.setup();
  render(<Main onLock={vi.fn()} />);
  await user.click(await screen.findByRole("button", { name: "Import…" }));
  expect(screen.getByRole("dialog", { name: "Import from 1Password" })).toBeInTheDocument();
});

test("a stale items reply does not overwrite a newer one", async () => {
  const user = userEvent.setup();
  const replies: ((v: ItemSummary[]) => void)[] = [];
  vi.mocked(api.items).mockReset().mockImplementation(() => new Promise((r) => replies.push(r)));
  render(<Main onLock={vi.fn()} />);
  await waitFor(() => expect(replies).toHaveLength(1));
  await user.type(screen.getByLabelText("Search"), "g");
  await waitFor(() => expect(replies).toHaveLength(2));
  replies[1]([{ ...github, id: "i2", title: "Second" }]);
  expect(await screen.findByText("Second")).toBeInTheDocument();
  replies[0]([{ ...github, title: "First" }]);
  await new Promise((r) => setTimeout(r, 20));
  expect(screen.getByText("Second")).toBeInTheDocument();
  expect(screen.queryByText("First")).not.toBeInTheDocument();
});

test("recently deleted lists deleted items and restores one", async () => {
  const user = userEvent.setup();
  render(<Main onLock={vi.fn()} />);
  await user.click(await screen.findByRole("button", { name: "Recently Deleted" }));
  await user.click(await screen.findByText("Old forum"));
  await user.click(screen.getByRole("button", { name: "Restore" }));
  expect(api.restoreItem).toHaveBeenCalledWith("d1");
  await waitFor(() => expect(api.deletedItems).toHaveBeenCalledTimes(2));
  expect(screen.getByRole("button", { name: "+ New" })).toBeDisabled();
});

test("settings open from the sidebar", async () => {
  const user = userEvent.setup();
  render(<Main onLock={vi.fn()} />);
  await user.click(await screen.findByRole("button", { name: "Settings…" }));
  expect(await screen.findByRole("dialog", { name: "Settings" })).toBeInTheDocument();
});

test("a pairing request from a browser opens the confirmation", async () => {
  render(<Main onLock={vi.fn()} />);
  await waitFor(() => expect(pairCallback).not.toBeNull());
  act(() => pairCallback!({ clientId: "c1", name: "Opera", code: "123456" }));
  expect(await screen.findByRole("dialog", { name: "Connect Opera?" })).toBeInTheDocument();
});

test("reloads vaults and items when the browser extension saves something", async () => {
  render(<Main onLock={vi.fn()} />);
  expect(await screen.findByText("GitHub")).toBeInTheDocument();
  vi.mocked(api.items).mockResolvedValue([github, { ...github, id: "i2", title: "shop.example" }]);
  const vaultCalls = vi.mocked(api.vaults).mock.calls.length;
  await waitFor(() => expect(changedCallback).not.toBeNull());
  act(() => changedCallback!());
  expect(await screen.findByText("shop.example")).toBeInTheDocument();
  expect(vi.mocked(api.vaults).mock.calls.length).toBeGreaterThan(vaultCalls);
});

test("renames the selected vault", async () => {
  const user = userEvent.setup();
  render(<Main onLock={vi.fn()} />);
  await user.click(await screen.findByRole("button", { name: /Work/ }));
  await user.click(screen.getByRole("button", { name: "Rename Work" }));
  await user.clear(screen.getByLabelText("New name for Work"));
  await user.type(screen.getByLabelText("New name for Work"), "Office{Enter}");
  expect(api.renameVault).toHaveBeenCalledWith("v2", "Office");
  await waitFor(() => expect(api.vaults).toHaveBeenCalledTimes(2));
});

test("deletes an empty vault after confirming", async () => {
  const user = userEvent.setup();
  render(<Main onLock={vi.fn()} />);
  await user.click(await screen.findByRole("button", { name: /Work/ }));
  await user.click(screen.getByRole("button", { name: "Delete Work" }));
  const dialog = screen.getByRole("alertdialog", { name: 'Delete vault "Work"?' });
  expect(dialog).toHaveTextContent("Recently Deleted");
  await user.click(screen.getByRole("button", { name: "Delete vault" }));
  expect(api.deleteVault).toHaveBeenCalledWith("v2");
  await waitFor(() => expect(lastFilter().vaultId).toBeNull());
});

test("a vault with items is not deleted", async () => {
  const user = userEvent.setup();
  render(<Main onLock={vi.fn()} />);
  await user.click(await screen.findByRole("button", { name: /Personal/ }));
  await user.click(screen.getByRole("button", { name: "Delete Personal" }));
  expect(await screen.findByRole("alert")).toHaveTextContent('"Personal" still has 1 item. Delete them first.');
  expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
  expect(api.deleteVault).not.toHaveBeenCalled();
});
