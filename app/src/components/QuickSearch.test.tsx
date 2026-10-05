import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { api, type ItemSummary } from "../api";
import { QuickSearch } from "./QuickSearch";

vi.mock("../api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api")>();
  return { ...actual, api: { ...actual.api, items: vi.fn(), quickCopy: vi.fn() } };
});

const row = (id: string, title: string, hasTotp = false): ItemSummary => ({
  id, vaultId: "v1", kind: "login", title, subtitle: "ivan", favorite: false, hasTotp, updatedAt: 0, damaged: false,
});

beforeEach(() => {
  vi.mocked(api.items).mockReset().mockResolvedValue([row("i1", "GitHub", true), row("i2", "GitLab")]);
  vi.mocked(api.quickCopy).mockReset().mockResolvedValue(undefined);
});

test("searches as you type", async () => {
  const user = userEvent.setup();
  render(<QuickSearch onDone={vi.fn()} />);
  expect(await screen.findByRole("option", { name: /GitHub/ })).toHaveAttribute("aria-selected", "true");
  await user.type(screen.getByLabelText("Quick search"), "git");
  await waitFor(() => expect(api.items).toHaveBeenLastCalledWith({ query: "git" }));
});

test("Enter copies the password, ⌘Enter the username, then closes", async () => {
  const user = userEvent.setup();
  const onDone = vi.fn();
  render(<QuickSearch onDone={onDone} />);
  await screen.findByRole("option", { name: /GitHub/ });
  await user.keyboard("{ArrowDown}{Enter}");
  expect(api.quickCopy).toHaveBeenLastCalledWith("i2", "password");
  await waitFor(() => expect(onDone).toHaveBeenCalledTimes(1));
  await user.keyboard("{ArrowUp}{Meta>}{Enter}{/Meta}");
  expect(api.quickCopy).toHaveBeenLastCalledWith("i1", "username");
});

test("⌘C copies the one-time code when nothing is selected in the box", async () => {
  const user = userEvent.setup();
  render(<QuickSearch onDone={vi.fn()} />);
  await screen.findByRole("option", { name: /GitHub/ });
  await user.keyboard("{Meta>}c{/Meta}");
  expect(api.quickCopy).toHaveBeenCalledWith("i1", "totp");
  await user.keyboard("{ArrowDown}{Meta>}c{/Meta}");
  expect(await screen.findByRole("alert")).toHaveTextContent("no one-time password");
  expect(api.quickCopy).toHaveBeenCalledTimes(1);
});

test("clicking a result copies its password", async () => {
  const user = userEvent.setup();
  render(<QuickSearch onDone={vi.fn()} />);
  await user.click(await screen.findByRole("option", { name: /GitLab/ }));
  expect(api.quickCopy).toHaveBeenCalledWith("i2", "password");
});

test("copy errors are shown", async () => {
  const user = userEvent.setup();
  vi.mocked(api.quickCopy).mockRejectedValue({ kind: "notFound", message: "This item has no password" });
  const onDone = vi.fn();
  render(<QuickSearch onDone={onDone} />);
  await screen.findByRole("option", { name: /GitHub/ });
  await user.keyboard("{Enter}");
  expect(await screen.findByRole("alert")).toHaveTextContent("This item has no password");
  expect(onDone).not.toHaveBeenCalled();
});
