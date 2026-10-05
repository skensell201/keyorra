import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { api } from "../api";
import { Unlock } from "./Unlock";

vi.mock("../api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api")>();
  return { ...actual, api: { ...actual.api, unlock: vi.fn(), startOver: vi.fn(), touchIdState: vi.fn(), unlockWithTouchId: vi.fn() } };
});

const touchOff = { available: true, enabled: false, passwordDue: false };
const touchOn = { available: true, enabled: true, passwordDue: false };

beforeEach(() => {
  vi.restoreAllMocks();
  vi.mocked(api.touchIdState).mockReset().mockResolvedValue(touchOff);
  vi.mocked(api.unlockWithTouchId).mockReset().mockResolvedValue(undefined);
  vi.mocked(api.unlock).mockReset();
  vi.mocked(api.startOver).mockReset().mockResolvedValue("/x/keyorra.db.unreadable-1");
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
  vi.mocked(api.unlock).mockRejectedValue({ kind: "notADatabase", message: "not a keyorra database: file is not a database" });
  render(<Unlock onUnlocked={vi.fn()} onStartOver={onStartOver} />);
  await user.type(screen.getByLabelText("Master password"), "whatever");
  await user.click(screen.getByRole("button", { name: "Unlock" }));
  expect(await screen.findByRole("heading", { name: "This file is not a Keyorra database" })).toBeInTheDocument();
  expect(screen.getByText(/never deleted/)).toBeInTheDocument();

  // A double click on "Start over…" must not also confirm: the second step is a dialog.
  await user.dblClick(screen.getByRole("button", { name: "Start over…" }));
  expect(api.startOver).not.toHaveBeenCalled();
  const dialog = screen.getByRole("alertdialog", { name: "Move the file aside and start over?" });
  await user.click(within(dialog).getByRole("button", { name: "Back" }));
  expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
  expect(api.startOver).not.toHaveBeenCalled();

  await user.click(screen.getByRole("button", { name: "Start over…" }));
  // Enter on the freshly opened dialog goes back, never forward.
  expect(screen.getByRole("button", { name: "Back" })).toHaveFocus();
  await user.click(screen.getByRole("button", { name: "Move aside and start over" }));
  expect(api.startOver).toHaveBeenCalledTimes(1);
  expect(await screen.findByText("/x/keyorra.db.unreadable-1")).toBeInTheDocument();
  expect(onStartOver).not.toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Set up a new vault" }));
  expect(onStartOver).toHaveBeenCalled();
});

test("Touch ID unlocks right away when the window is in front", async () => {
  vi.spyOn(document, "hasFocus").mockReturnValue(true);
  vi.mocked(api.touchIdState).mockResolvedValue(touchOn);
  const onUnlocked = vi.fn();
  render(<Unlock onUnlocked={onUnlocked} onStartOver={vi.fn()} />);
  await waitFor(() => expect(onUnlocked).toHaveBeenCalled());
  expect(api.unlockWithTouchId).toHaveBeenCalledTimes(1);
});

test("Touch ID waits until the window comes to the front", async () => {
  vi.spyOn(document, "hasFocus").mockReturnValue(false);
  vi.mocked(api.touchIdState).mockResolvedValue(touchOn);
  render(<Unlock onUnlocked={vi.fn()} onStartOver={vi.fn()} />);
  expect(await screen.findByRole("button", { name: "Unlock with Touch ID" })).toBeInTheDocument();
  expect(api.unlockWithTouchId).not.toHaveBeenCalled();
  act(() => {
    window.dispatchEvent(new Event("focus"));
  });
  await waitFor(() => expect(api.unlockWithTouchId).toHaveBeenCalledTimes(1));
  act(() => {
    window.dispatchEvent(new Event("focus"));
  });
  expect(api.unlockWithTouchId).toHaveBeenCalledTimes(1);
});

test("a dismissed prompt leaves the password form; the button tries again", async () => {
  const user = userEvent.setup();
  vi.spyOn(document, "hasFocus").mockReturnValue(true);
  vi.mocked(api.touchIdState).mockResolvedValue(touchOn);
  vi.mocked(api.unlockWithTouchId).mockRejectedValueOnce({ kind: "cancelled", message: "Cancelled" });
  const onUnlocked = vi.fn();
  render(<Unlock onUnlocked={onUnlocked} onStartOver={vi.fn()} />);
  const button = await screen.findByRole("button", { name: "Unlock with Touch ID" });
  await waitFor(() => expect(button).toBeEnabled());
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  await user.click(button);
  await waitFor(() => expect(onUnlocked).toHaveBeenCalled());
});

test("when the password is required, Touch ID steps aside with the reason", async () => {
  vi.spyOn(document, "hasFocus").mockReturnValue(true);
  vi.mocked(api.touchIdState).mockResolvedValue(touchOn);
  vi.mocked(api.unlockWithTouchId).mockRejectedValue({
    kind: "passwordRequired",
    message: "Your fingerprints changed. Unlock with your master password, then turn Touch ID on again in Settings.",
  });
  render(<Unlock onUnlocked={vi.fn()} onStartOver={vi.fn()} />);
  expect(await screen.findByRole("alert")).toHaveTextContent("fingerprints changed");
  expect(screen.queryByRole("button", { name: "Unlock with Touch ID" })).not.toBeInTheDocument();
});

test("every 14 days the password is asked for instead", async () => {
  vi.spyOn(document, "hasFocus").mockReturnValue(true);
  vi.mocked(api.touchIdState).mockResolvedValue({ ...touchOn, passwordDue: true });
  render(<Unlock onUnlocked={vi.fn()} onStartOver={vi.fn()} />);
  expect(await screen.findByText(/every 14 days/)).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Unlock with Touch ID" })).not.toBeInTheDocument();
  expect(api.unlockWithTouchId).not.toHaveBeenCalled();
});
