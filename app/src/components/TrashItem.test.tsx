import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { api, type ItemSummary } from "../api";
import { TrashItem } from "./TrashItem";

vi.mock("../api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api")>();
  return { ...actual, api: { ...actual.api, restoreItem: vi.fn() } };
});

const deleted: ItemSummary = {
  id: "d1", vaultId: "v1", kind: "login", title: "Old forum", subtitle: "ivan",
  favorite: false, hasTotp: false, updatedAt: 0, damaged: false,
};

beforeEach(() => {
  vi.mocked(api.restoreItem).mockReset().mockResolvedValue(undefined);
});

test("restores the item", async () => {
  const user = userEvent.setup();
  const onRestored = vi.fn();
  render(<TrashItem item={deleted} onRestored={onRestored} />);
  expect(screen.getByRole("heading", { name: "Old forum" })).toBeInTheDocument();
  expect(screen.getByText(/removed for good 30 days/)).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Restore" }));
  expect(api.restoreItem).toHaveBeenCalledWith("d1");
  await waitFor(() => expect(onRestored).toHaveBeenCalled());
});

test("shows a restore error", async () => {
  const user = userEvent.setup();
  vi.mocked(api.restoreItem).mockRejectedValue({ kind: "notFound", message: "not found: deleted item d1" });
  render(<TrashItem item={deleted} onRestored={vi.fn()} />);
  await user.click(screen.getByRole("button", { name: "Restore" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("not found");
});
