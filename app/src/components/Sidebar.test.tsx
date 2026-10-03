import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, test, vi } from "vitest";
import { Sidebar } from "./Sidebar";

const vaults = [
  { id: "v1", name: "Personal", itemCount: 3 },
  { id: "v2", name: "Datagile", itemCount: 2 },
];

function setup() {
  const props = { onSelect: vi.fn(), onNewVault: vi.fn(), onImport: vi.fn(), onLock: vi.fn() };
  render(<Sidebar vaults={vaults} selection={{ kind: "all" }} {...props} />);
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
  await user.click(screen.getByRole("button", { name: "Import from 1Password…" }));
  expect(props.onImport).toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Lock" }));
  expect(props.onLock).toHaveBeenCalled();
});
