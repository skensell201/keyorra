import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { api } from "../api";
import { Unlock } from "./Unlock";

vi.mock("../api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api")>();
  return { ...actual, api: { ...actual.api, unlock: vi.fn() } };
});

beforeEach(() => {
  vi.mocked(api.unlock).mockReset();
});

test("unlocks with the master password", async () => {
  const user = userEvent.setup();
  const onUnlocked = vi.fn();
  vi.mocked(api.unlock).mockResolvedValue(undefined);
  render(<Unlock onUnlocked={onUnlocked} />);
  await user.type(screen.getByLabelText("Master password"), "correct horse battery");
  await user.click(screen.getByRole("button", { name: "Unlock" }));
  expect(api.unlock).toHaveBeenCalledWith("correct horse battery");
  await waitFor(() => expect(onUnlocked).toHaveBeenCalled());
});

test("wrong password shows an error and clears the field", async () => {
  const user = userEvent.setup();
  vi.mocked(api.unlock).mockRejectedValue({ kind: "wrongPassword", message: "incorrect password" });
  render(<Unlock onUnlocked={vi.fn()} />);
  await user.type(screen.getByLabelText("Master password"), "nope");
  await user.click(screen.getByRole("button", { name: "Unlock" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Incorrect password");
  expect(screen.getByLabelText("Master password")).toHaveValue("");
});

test("throttling disables the button and shows the wait", async () => {
  const user = userEvent.setup();
  vi.mocked(api.unlock).mockRejectedValue({ kind: "throttled", message: "Too many attempts. Try again in 3 s.", retryAfter: 3 });
  render(<Unlock onUnlocked={vi.fn()} />);
  await user.type(screen.getByLabelText("Master password"), "nope");
  await user.click(screen.getByRole("button", { name: "Unlock" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Try again in 3 s.");
  await user.type(screen.getByLabelText("Master password"), "x");
  expect(screen.getByRole("button", { name: "Unlock" })).toBeDisabled();
});
