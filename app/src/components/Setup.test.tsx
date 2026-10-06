import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { api } from "../api";
import { Setup } from "./Setup";

vi.mock("../api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api")>();
  return { ...actual, api: { ...actual.api, create: vi.fn(), joinSync: vi.fn() } };
});

beforeEach(() => {
  vi.mocked(api.create).mockReset();
  vi.mocked(api.joinSync).mockReset();
});

test("creates the vault once both passwords match and are long enough", async () => {
  const user = userEvent.setup();
  const onDone = vi.fn();
  vi.mocked(api.create).mockResolvedValue(undefined);
  render(<Setup onDone={onDone} />);
  const submit = screen.getByRole("button", { name: "Create vault" });
  expect(submit).toBeDisabled();

  await user.type(screen.getByLabelText("Master password"), "short");
  expect(screen.getByText("Use at least 10 characters")).toBeInTheDocument();
  await user.clear(screen.getByLabelText("Master password"));
  await user.type(screen.getByLabelText("Master password"), "correct horse battery");
  await user.type(screen.getByLabelText("Confirm password"), "correct horse");
  expect(screen.getByText("Passwords don't match")).toBeInTheDocument();
  expect(submit).toBeDisabled();
  await user.type(screen.getByLabelText("Confirm password"), " battery");

  await user.click(submit);
  expect(api.create).toHaveBeenCalledWith("correct horse battery");
  await waitFor(() => expect(onDone).toHaveBeenCalled());
});

test("shows a backend error", async () => {
  const user = userEvent.setup();
  vi.mocked(api.create).mockRejectedValue({ kind: "invalid", message: "A vault already exists on this Mac" });
  render(<Setup onDone={vi.fn()} />);
  await user.type(screen.getByLabelText("Master password"), "correct horse battery");
  await user.type(screen.getByLabelText("Confirm password"), "correct horse battery");
  await user.click(screen.getByRole("button", { name: "Create vault" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("A vault already exists on this Mac");
});

test("a new Mac can join a synced account instead", async () => {
  const user = userEvent.setup();
  const onDone = vi.fn();
  vi.mocked(api.joinSync).mockResolvedValue({
    mode: "new",
    keyCode: "0a1b-2c3d-4e5f",
    copied: 0,
    trashedLeft: 0,
    damaged: 0,
  });
  render(<Setup onDone={onDone} />);
  await user.click(screen.getByRole("button", { name: /Join your synced account/ }));
  await user.type(screen.getByLabelText("Master password"), "correct horse battery");
  await user.type(screen.getByLabelText("Setup code or Secret Key"), "KEYORRA-SETUP-1-XYZ");
  await user.click(screen.getByRole("button", { name: "Join" }));
  expect(await screen.findByTestId("key-code")).toHaveTextContent("0a1b-2c3d-4e5f");
  await user.click(screen.getByRole("button", { name: "Continue" }));
  expect(onDone).toHaveBeenCalled();
});
