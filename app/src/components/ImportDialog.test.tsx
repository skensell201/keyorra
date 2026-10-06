import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { open } from "@tauri-apps/plugin-dialog";
import { beforeEach, expect, test, vi } from "vitest";
import { api } from "../api";
import { ImportDialog } from "./ImportDialog";

vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn() }));
vi.mock("../api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api")>();
  return { ...actual, api: { ...actual.api, importPreview: vi.fn(), importApply: vi.fn() } };
});

beforeEach(() => {
  vi.mocked(open).mockReset().mockResolvedValue("/Users/me/Downloads/export.1pux");
  vi.mocked(api.importPreview).mockReset().mockResolvedValue({
    vaults: [{ name: "Personal", items: 120 }, { name: "Datagile", items: 34 }],
    skipped: [{ title: "Passport scan / passport.pdf", reason: "attachment missing from export" }],
    totalItems: 154,
  });
  vi.mocked(api.importApply).mockReset().mockResolvedValue({ vaults: 2, items: 154, attachments: 3 });
});

test("pick, preview, import", async () => {
  const user = userEvent.setup();
  const onImported = vi.fn();
  const onClose = vi.fn();
  render(<ImportDialog onClose={onClose} onImported={onImported} />);

  await user.click(screen.getByRole("button", { name: "Choose export file" }));
  expect(api.importPreview).toHaveBeenCalledWith("/Users/me/Downloads/export.1pux");
  expect(await screen.findByText("Personal — 120 items")).toBeInTheDocument();
  expect(screen.getByText("Datagile — 34 items")).toBeInTheDocument();
  expect(screen.getByText(/attachment missing from export/)).toBeInTheDocument();

  await user.click(screen.getByRole("button", { name: "Import 154 items" }));
  expect(await screen.findByText(/Imported 154 items into 2 vaults/)).toBeInTheDocument();
  expect(onImported).toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Done" }));
  expect(onClose).toHaveBeenCalled();
});

test("cancelling the file picker stays on the first step", async () => {
  const user = userEvent.setup();
  vi.mocked(open).mockResolvedValue(null);
  render(<ImportDialog onClose={vi.fn()} onImported={vi.fn()} />);
  await user.click(screen.getByRole("button", { name: "Choose export file" }));
  expect(api.importPreview).not.toHaveBeenCalled();
  expect(screen.getByRole("button", { name: "Choose export file" })).toBeInTheDocument();
});

test("shows parse errors and can be cancelled", async () => {
  const user = userEvent.setup();
  const onClose = vi.fn();
  vi.mocked(api.importPreview).mockRejectedValue({ kind: "invalid", message: "invalid data: not a .1pux file" });
  render(<ImportDialog onClose={onClose} onImported={vi.fn()} />);
  await user.click(screen.getByRole("button", { name: "Choose export file" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("not a .1pux file");
  await user.click(screen.getByRole("button", { name: "Cancel" }));
  expect(onClose).toHaveBeenCalled();
});

test("Escape closes the dialog", async () => {
  const onClose = vi.fn();
  render(<ImportDialog onClose={onClose} onImported={vi.fn()} />);
  await userEvent.setup().keyboard("{Escape}");
  expect(onClose).toHaveBeenCalled();
});

test("singular counts read naturally", async () => {
  const user = userEvent.setup();
  vi.mocked(api.importApply).mockResolvedValue({ vaults: 1, items: 1, attachments: 0 });
  render(<ImportDialog onClose={vi.fn()} onImported={vi.fn()} />);
  await user.click(screen.getByRole("button", { name: "Choose export file" }));
  await user.click(await screen.findByRole("button", { name: "Import 154 items" }));
  expect(await screen.findByText("Imported 1 item into 1 vault (0 attachments).")).toBeInTheDocument();
});
