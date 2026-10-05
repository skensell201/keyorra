import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { api } from "../api";
import { Unlock } from "./Unlock";

vi.mock("../api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api")>();
  return { ...actual, api: { ...actual.api, unlock: vi.fn(), startOver: vi.fn() } };
});

beforeEach(() => {
  vi.mocked(api.unlock).mockReset();
  vi.mocked(api.startOver).mockReset().mockResolvedValue("/x/keepsake.db.unreadable-1");
});

test("unlocks with the master password", async () => {
  const user = userEvent.setup();
  const onUnlocked = vi.fn();
  vi.mocked(api.unlock).mockResolvedValue(undefined);
  render(<Unlock onUnlocked={onUnlocked} onStartOver={vi.fn()} />);
  await user.type(screen.getByLabelText("Master password"), "correct horse battery");
  await user.click(screen.getByRole("button", { name: "Unlock" }));
  expect(api.unlock).toHaveBeenCalledWith("correct horse battery");
  await waitFor(() => expect(onUnlocked).toHaveBeenCalled());
});

test("wrong password shows an error and clears the field", async () => {
  const user = userEvent.setup();
  vi.mocked(api.unlock).mockRejectedValue({ kind: "wrongPassword", message: "incorrect password" });
  render(<Unlock onUnlocked={vi.fn()} onStartOver={vi.fn()} />);
  await user.type(screen.getByLabelText("Master password"), "nope");
  await user.click(screen.getByRole("button", { name: "Unlock" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Incorrect password");
  expect(screen.getByLabelText("Master password")).toHaveValue("");
});

test("throttling disables the button and shows the wait", async () => {
  const user = userEvent.setup();
  vi.mocked(api.unlock).mockRejectedValue({ kind: "throttled", message: "Too many attempts. Try again in 3 s.", retryAfter: 3 });
  render(<Unlock onUnlocked={vi.fn()} onStartOver={vi.fn()} />);
  await user.type(screen.getByLabelText("Master password"), "nope");
  await user.click(screen.getByRole("button", { name: "Unlock" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Try again in 3 s.");
  await user.type(screen.getByLabelText("Master password"), "x");
  expect(screen.getByRole("button", { name: "Unlock" })).toBeDisabled();
});

test("the throttle error clears when the countdown ends", async () => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  try {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    vi.mocked(api.unlock).mockRejectedValue({ kind: "throttled", message: "Too many attempts", retryAfter: 2 });
    render(<Unlock onUnlocked={vi.fn()} onStartOver={vi.fn()} />);
    await user.type(screen.getByLabelText("Master password"), "nope");
    await user.click(screen.getByRole("button", { name: "Unlock" }));
    expect(await screen.findByRole("alert")).toBeInTheDocument();
    for (let i = 0; i < 2; i++) {
      await act(async () => {
        await vi.advanceTimersByTimeAsync(1000);
      });
    }
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    await user.type(screen.getByLabelText("Master password"), "x");
    expect(screen.getByRole("button", { name: "Unlock" })).toBeEnabled();
  } finally {
    vi.useRealTimers();
  }
});

test("an unreadable database offers to start over", async () => {
  const user = userEvent.setup();
  const onStartOver = vi.fn();
  vi.mocked(api.unlock).mockRejectedValue({ kind: "notADatabase", message: "not a keepsake database: file is not a database" });
  render(<Unlock onUnlocked={vi.fn()} onStartOver={onStartOver} />);
  await user.type(screen.getByLabelText("Master password"), "whatever");
  await user.click(screen.getByRole("button", { name: "Unlock" }));
  expect(await screen.findByRole("heading", { name: "This file is not a Keepsake database" })).toBeInTheDocument();
  expect(screen.getByText(/never deleted/)).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Start over…" }));
  expect(api.startOver).not.toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Move it aside and start over" }));
  expect(api.startOver).toHaveBeenCalled();
  await waitFor(() => expect(onStartOver).toHaveBeenCalled());
});
