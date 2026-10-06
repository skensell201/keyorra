import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, test, vi } from "vitest";
import { api } from "../api";
import { EmergencyKit, groupHex } from "./EmergencyKit";

vi.mock("../api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api")>();
  return { ...actual, api: { ...actual.api, copySecret: vi.fn() } };
});

test("the kit shows the account and Secret Key, copies the setup code concealed", async () => {
  const user = userEvent.setup();
  vi.mocked(api.copySecret).mockResolvedValue(undefined);
  render(
    <EmergencyKit
      kit={{ accountId: "0123456789abcdef0123456789abcdef", secretKey: "A3KX-ABCDE", setupCode: "KEYORRA-SETUP-1-XYZ" }}
      location="/sync/Keyorra/0123"
      onDone={vi.fn()}
    />,
  );
  expect(screen.getByText("0123 4567 89ab cdef 0123 4567 89ab cdef")).toBeInTheDocument();
  expect(screen.getByText(/Don't save the kit as a file in iCloud Drive/)).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Copy setup code" }));
  expect(api.copySecret).toHaveBeenCalledWith("KEYORRA-SETUP-1-XYZ");
  expect(await screen.findByText(/clears from the clipboard in 90 seconds/)).toBeInTheDocument();
  expect(groupHex("abcdef")).toBe("abcd ef");
});
