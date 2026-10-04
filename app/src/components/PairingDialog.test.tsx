import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { api } from "../api";
import { PairingDialog } from "./PairingDialog";

vi.mock("../api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api")>();
  return { ...actual, api: { ...actual.api, approvePairing: vi.fn(), denyPairing: vi.fn() } };
});

beforeEach(() => {
  vi.mocked(api.approvePairing).mockReset().mockResolvedValue(undefined);
  vi.mocked(api.denyPairing).mockReset().mockResolvedValue(undefined);
});

const request = { clientId: "c1", name: "Chrome", code: "381262" };

test("shows the browser and the code and connects", async () => {
  const user = userEvent.setup();
  const onDone = vi.fn();
  render(<PairingDialog request={request} onDone={onDone} />);
  expect(screen.getByRole("dialog", { name: "Connect Chrome?" })).toBeInTheDocument();
  expect(screen.getByText("381 262")).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Connect" }));
  expect(api.approvePairing).toHaveBeenCalledWith("c1");
  await waitFor(() => expect(onDone).toHaveBeenCalled());
});

test("deny", async () => {
  const user = userEvent.setup();
  const onDone = vi.fn();
  render(<PairingDialog request={request} onDone={onDone} />);
  await user.click(screen.getByRole("button", { name: "Deny" }));
  expect(api.denyPairing).toHaveBeenCalledWith("c1");
  await waitFor(() => expect(onDone).toHaveBeenCalled());
});

test("shows an expired request", async () => {
  const user = userEvent.setup();
  vi.mocked(api.approvePairing).mockRejectedValue({ kind: "notFound", message: "This request has expired" });
  render(<PairingDialog request={request} onDone={vi.fn()} />);
  await user.click(screen.getByRole("button", { name: "Connect" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("This request has expired");
});
