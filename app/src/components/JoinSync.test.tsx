import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { api } from "../api";
import { JoinResult, JoinSync } from "./JoinSync";

vi.mock("../api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api")>();
  return { ...actual, api: { ...actual.api, joinSync: vi.fn() } };
});

beforeEach(() => {
  vi.mocked(api.joinSync).mockReset();
});

test("joins with the password and the setup code", async () => {
  const user = userEvent.setup();
  const outcome = { mode: "new" as const, keyCode: "0a1b-2c3d-4e5f", copied: 0, trashedLeft: 0, damaged: 0 };
  vi.mocked(api.joinSync).mockResolvedValue(outcome);
  const onJoined = vi.fn();
  render(<JoinSync onJoined={onJoined} />);
  await user.type(screen.getByLabelText("Master password"), "correct horse battery");
  await user.type(screen.getByLabelText("Setup code or Secret Key"), "  KEYORRA-SETUP-1-XYZ ");
  await user.click(screen.getByRole("button", { name: "Join" }));
  expect(api.joinSync).toHaveBeenCalledWith("correct horse battery", "KEYORRA-SETUP-1-XYZ");
  expect(onJoined).toHaveBeenCalledWith(outcome);
});

test("a wrong password or key says so", async () => {
  const user = userEvent.setup();
  vi.mocked(api.joinSync).mockRejectedValue({ kind: "wrongPassword", message: "x" });
  render(<JoinSync onJoined={vi.fn()} />);
  await user.type(screen.getByLabelText("Master password"), "nope nope nope");
  await user.type(screen.getByLabelText("Setup code or Secret Key"), "A3KX");
  await user.click(screen.getByRole("button", { name: "Join" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("The master password or the Secret Key is wrong");
});

test("after joining: the code to compare, and what was carried over", () => {
  render(
    <JoinResult
      outcome={{ mode: "carriedOver", keyCode: "0a1b-2c3d-4e5f", copied: 7, trashedLeft: 2, damaged: 1 }}
      onDone={vi.fn()}
    />,
  );
  expect(screen.getByTestId("key-code")).toHaveTextContent("0a1b-2c3d-4e5f");
  expect(screen.getByText(/7 item\(s\) from this Mac were copied/)).toHaveTextContent(
    "2 in Recently Deleted and 1 unreadable item(s) stayed in the old file",
  );
});
