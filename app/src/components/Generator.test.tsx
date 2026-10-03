import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { api } from "../api";
import { Generator } from "./Generator";

vi.mock("../api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api")>();
  return { ...actual, api: { ...actual.api, generate: vi.fn() } };
});

beforeEach(() => {
  vi.mocked(api.generate).mockReset().mockResolvedValue("Gen-123");
});

const lastRequest = () => vi.mocked(api.generate).mock.lastCall![0];

test("generates with defaults and on every option change", async () => {
  render(<Generator onUse={vi.fn()} />);
  expect(await screen.findByText("Gen-123")).toBeInTheDocument();
  expect(lastRequest()).toMatchObject({ kind: "password", length: 20, symbols: true });

  fireEvent.change(screen.getByLabelText(/Length/), { target: { value: "32" } });
  await waitFor(() => expect(lastRequest().length).toBe(32));

  await userEvent.setup().click(screen.getByRole("button", { name: "Passphrase" }));
  await waitFor(() => expect(lastRequest().kind).toBe("passphrase"));
  expect(screen.getByLabelText(/Words/)).toBeInTheDocument();
});

test("use passes the generated value", async () => {
  const user = userEvent.setup();
  const onUse = vi.fn();
  render(<Generator onUse={onUse} />);
  await screen.findByText("Gen-123");
  await user.click(screen.getByRole("button", { name: "Use" }));
  expect(onUse).toHaveBeenCalledWith("Gen-123");
});

test("ignores out-of-order replies", async () => {
  const replies: ((v: string) => void)[] = [];
  vi.mocked(api.generate).mockReset().mockImplementation(() => new Promise<string>((r) => replies.push(r)));
  render(<Generator onUse={vi.fn()} />);
  fireEvent.change(screen.getByLabelText(/Length/), { target: { value: "32" } });
  await waitFor(() => expect(replies).toHaveLength(2));
  replies[1]("second");
  expect(await screen.findByText("second")).toBeInTheDocument();
  replies[0]("first");
  await new Promise((r) => setTimeout(r, 20));
  expect(screen.getByText("second")).toBeInTheDocument();
  expect(screen.queryByText("first")).not.toBeInTheDocument();
});

test("a failed generation disables Use", async () => {
  render(<Generator onUse={vi.fn()} />);
  await screen.findByText("Gen-123");
  vi.mocked(api.generate).mockRejectedValue({ kind: "other", message: "boom" });
  await userEvent.setup().click(screen.getByRole("button", { name: "Regenerate" }));
  expect(await screen.findByText("boom")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Use" })).toBeDisabled();
});
