import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, test, vi } from "vitest";
import { Sidebar, type Selection } from "./Sidebar";

const vaults = [
  { id: "v1", name: "Personal", itemCount: 3 },
  { id: "v2", name: "Datagile", itemCount: 2 },
];

function setup(selection: Selection = { kind: "all" }) {
  const props = {
    onSelect: vi.fn(),
    onNewVault: vi.fn(),
    onRenameVault: vi.fn(),
    onDeleteVault: vi.fn(),
    onImport: vi.fn(),
    onLock: vi.fn(),
    onSettings: vi.fn(),
  };
  render(<Sidebar vaults={vaults} selection={selection} {...props} />);
  return props;
}

test("lists vaults with counts and selects them", async () => {
  const user = userEvent.setup();
  const props = setup();
  expect(screen.getByRole("button", { name: /All items/ })).toHaveTextContent("5");
  expect(screen.getByRole("button", { name: /All items/ })).toHaveAttribute("aria-current", "true");
  await user.click(screen.getByRole("button", { name: /Datagile/ }));
  expect(props.onSelect).toHaveBeenCalledWith({ kind: "vault", id: "v2" });
  await user.click(screen.getByRole("button", { name: "Favorites" }));
  expect(props.onSelect).toHaveBeenCalledWith({ kind: "favorites" });
});

test("creates a vault, imports and locks", async () => {
  const user = userEvent.setup();
  const props = setup();
  await user.click(screen.getByRole("button", { name: "+ New vault" }));
  await user.type(screen.getByLabelText("Vault name"), "Work{Enter}");
  expect(props.onNewVault).toHaveBeenCalledWith("Work");
  await user.click(screen.getByRole("button", { name: "Import…" }));
  expect(props.onImport).toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Lock" }));
  expect(props.onLock).toHaveBeenCalled();
});

test("recently deleted and settings", async () => {
  const user = userEvent.setup();
  const props = setup();
  await user.click(screen.getByRole("button", { name: "Recently Deleted" }));
  expect(props.onSelect).toHaveBeenCalledWith({ kind: "trash" });
  await user.click(screen.getByRole("button", { name: "Settings…" }));
  expect(props.onSettings).toHaveBeenCalled();
});

test("the selected vault can be renamed and deleted", async () => {
  const user = userEvent.setup();
  const props = setup({ kind: "vault", id: "v2" });
  expect(screen.queryByRole("button", { name: "Rename Personal" })).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Rename Datagile" }));
  const input = screen.getByLabelText("New name for Datagile");
  expect(input).toHaveValue("Datagile");
  await user.clear(input);
  await user.type(input, "Work{Enter}");
  expect(props.onRenameVault).toHaveBeenCalledWith("v2", "Work");
  await user.click(screen.getByRole("button", { name: "Delete Datagile" }));
  expect(props.onDeleteVault).toHaveBeenCalledWith(vaults[1]);
});

test("Escape cancels a rename", async () => {
  const user = userEvent.setup();
  const props = setup({ kind: "vault", id: "v1" });
  await user.click(screen.getByRole("button", { name: "Rename Personal" }));
  await user.type(screen.getByLabelText("New name for Personal"), "x{Escape}");
  expect(props.onRenameVault).not.toHaveBeenCalled();
  expect(screen.queryByLabelText("New name for Personal")).not.toBeInTheDocument();
});
