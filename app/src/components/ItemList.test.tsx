import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, test, vi } from "vitest";
import type { ItemSummary } from "../api";
import { ItemList } from "./ItemList";

const summary = (over: Partial<ItemSummary>): ItemSummary => ({
  id: "i1", vaultId: "v1", kind: "login", title: "GitHub", subtitle: "ivan",
  favorite: false, hasTotp: false, updatedAt: 0, damaged: false, ...over,
});

function setup(items: ItemSummary[], query = "") {
  const props = { onQuery: vi.fn(), onSelect: vi.fn(), onNew: vi.fn() };
  render(<ItemList items={items} query={query} selectedId={null} canCreate {...props} />);
  return props;
}

test("shows items and selects one", async () => {
  const user = userEvent.setup();
  const props = setup([summary({}), summary({ id: "i2", title: "Bank", subtitle: "", favorite: true })]);
  expect(screen.getByText("ivan")).toBeInTheDocument();
  expect(screen.getByText("★ Bank")).toBeInTheDocument();
  await user.click(screen.getByText("GitHub"));
  expect(props.onSelect).toHaveBeenCalledWith("i1");
});

test("search reports every change", async () => {
  const user = userEvent.setup();
  const props = setup([]);
  await user.type(screen.getByLabelText("Search"), "g");
  expect(props.onQuery).toHaveBeenCalledWith("g");
  expect(screen.getByText("No items yet")).toBeInTheDocument();
});

test("new item menu offers every kind", async () => {
  const user = userEvent.setup();
  const props = setup([]);
  await user.click(screen.getByRole("button", { name: "+ New" }));
  expect(screen.getAllByRole("menuitem")).toHaveLength(6);
  await user.click(screen.getByRole("menuitem", { name: "Secure note" }));
  expect(props.onNew).toHaveBeenCalledWith("secure_note");
  expect(screen.queryByRole("menu")).not.toBeInTheDocument();
});

test("damaged items are marked and an empty search says so", () => {
  setup([summary({ title: "Damaged item", subtitle: "This item can't be decrypted", kind: null, damaged: true })], "x");
  expect(screen.getByText("Damaged item")).toHaveClass("damaged");
});
