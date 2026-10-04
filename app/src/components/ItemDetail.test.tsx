import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { api } from "../api";
import { loginItem } from "../test/fixtures";
import { ItemDetail } from "./ItemDetail";

vi.mock("../api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api")>();
  return {
    ...actual,
    api: { ...actual.api, item: vi.fn(), totp: vi.fn(), copyField: vi.fn(), deleteItem: vi.fn() },
  };
});

beforeEach(() => {
  vi.mocked(api.item).mockReset().mockResolvedValue(loginItem());
  vi.mocked(api.totp).mockReset().mockResolvedValue({ code: "123456", secondsLeft: 12, period: 30 });
  vi.mocked(api.copyField).mockReset().mockResolvedValue(undefined);
  vi.mocked(api.deleteItem).mockReset().mockResolvedValue(undefined);
});

function setup() {
  const props = { onEdit: vi.fn(), onDeleted: vi.fn() };
  render(<ItemDetail itemId="i1" {...props} />);
  return props;
}

test("shows fields with concealed values masked until revealed", async () => {
  const user = userEvent.setup();
  setup();
  expect(await screen.findByRole("heading", { name: "GitHub" })).toBeInTheDocument();
  expect(screen.getByText("ivan")).toBeInTheDocument();
  expect(screen.queryByText("hunter2")).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Reveal password" }));
  expect(screen.getByText("hunter2")).toBeInTheDocument();
  expect(screen.getByRole("heading", { name: "Security" })).toBeInTheDocument();
  expect(screen.getByText("12/2027")).toBeInTheDocument();
  expect(screen.getByText("main account")).toBeInTheDocument();
  expect(screen.getByText("https://github.com/login")).toBeInTheDocument();
});

test("copies a field and confirms", async () => {
  const user = userEvent.setup();
  setup();
  await user.click(await screen.findByRole("button", { name: "Copy username" }));
  expect(api.copyField).toHaveBeenCalledWith("i1", "username");
  expect(screen.getByRole("status")).toHaveTextContent("Copied");
});

test("shows the current one-time code and copies it", async () => {
  const user = userEvent.setup();
  setup();
  expect(await screen.findByText("123 456")).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Copy one-time password" }));
  expect(api.copyField).toHaveBeenCalledWith("i1", "totp");
});

test("edit and delete", async () => {
  const user = userEvent.setup();
  const props = setup();
  await user.click(await screen.findByRole("button", { name: "Edit" }));
  expect(props.onEdit).toHaveBeenCalledWith(loginItem());
  await user.click(screen.getByRole("button", { name: "Delete" }));
  await user.click(screen.getByRole("button", { name: "Move to trash" }));
  expect(api.deleteItem).toHaveBeenCalledWith("i1");
  await waitFor(() => expect(props.onDeleted).toHaveBeenCalled());
});

test("shows a load error", async () => {
  vi.mocked(api.item).mockRejectedValue({ kind: "notFound", message: "not found: item i1" });
  setup();
  expect(await screen.findByRole("alert")).toHaveTextContent("not found");
});

test("a failed copy shows a dismissible banner and keeps the item", async () => {
  const user = userEvent.setup();
  vi.mocked(api.copyField).mockRejectedValue({ kind: "other", message: "clipboard unavailable" });
  setup();
  await user.click(await screen.findByRole("button", { name: "Copy username" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("clipboard unavailable");
  expect(screen.getByRole("heading", { name: "GitHub" })).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Dismiss" }));
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
});

test("the copied toast disappears after a few seconds", async () => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  try {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    setup();
    await user.click(await screen.findByRole("button", { name: "Copy username" }));
    expect(screen.getByRole("status")).toHaveTextContent("cleared automatically");
    await act(async () => {
      await vi.advanceTimersByTimeAsync(3100);
    });
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  } finally {
    vi.useRealTimers();
  }
});

test("a failing one-time code shows an error in its row", async () => {
  vi.mocked(api.totp).mockRejectedValue({ kind: "invalid", message: "bad secret" });
  setup();
  expect(await screen.findByText("Invalid one-time password")).toBeInTheDocument();
});
