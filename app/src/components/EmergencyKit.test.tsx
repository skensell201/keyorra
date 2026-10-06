import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, test, vi } from "vitest";
import { api } from "../api";
import { EmergencyKit, groupHex } from "./EmergencyKit";

vi.mock("../api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api")>();
  return { ...actual, api: { ...actual.api, copySetupCode: vi.fn() } };
});

const kit = { accountId: "0123456789abcdef0123456789abcdef", secretKey: "A3KX-ABCDE", location: "/sync/Keyorra/0123" };

test("the kit shows the account, Secret Key and folder, copies the setup code from Rust", async () => {
  const user = userEvent.setup();
  vi.mocked(api.copySetupCode).mockResolvedValue(undefined);
  render(<EmergencyKit kit={kit} onDone={vi.fn()} />);
  expect(screen.getByText("0123 4567 89ab cdef 0123 4567 89ab cdef")).toBeInTheDocument();
  expect(screen.getByText("/sync/Keyorra/0123")).toBeInTheDocument();
  expect(screen.getByText(/Don't save the kit as a file in iCloud Drive/)).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Copy setup code" }));
  // Review A3: the setup code never reaches the web view; Rust reads and copies it.
  expect(api.copySetupCode).toHaveBeenCalledWith();
  expect(await screen.findByText(/clears from the clipboard in 90 seconds/)).toBeInTheDocument();
  expect(groupHex("abcdef")).toBe("abcd ef");
});

test("review A3: the kit's status is not a second region named Emergency Kit", () => {
  render(<EmergencyKit kit={kit} onDone={vi.fn()} />);
  expect(screen.getAllByLabelText("Emergency Kit")).toHaveLength(1);
});

test("copying after the password expired says what to do", async () => {
  const user = userEvent.setup();
  vi.mocked(api.copySetupCode).mockRejectedValue({ kind: "passwordRequired", message: "Enter your master password" });
  render(<EmergencyKit kit={{ ...kit, location: null }} onDone={vi.fn()} />);
  expect(screen.queryByText("Sync folder")).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Copy setup code" }));
  expect(await screen.findByText(/Open the Emergency Kit again/)).toBeInTheDocument();
});
