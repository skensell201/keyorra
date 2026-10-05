import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, test, vi } from "vitest";
import { ConfirmDialog } from "./ConfirmDialog";

test("confirms, cancels and closes on Escape", async () => {
  const user = userEvent.setup();
  const onConfirm = vi.fn();
  const onCancel = vi.fn();
  render(
    <ConfirmDialog title="Delete vault Work?" confirmLabel="Delete vault" danger onConfirm={onConfirm} onCancel={onCancel}>
      It is empty.
    </ConfirmDialog>,
  );
  expect(screen.getByRole("alertdialog", { name: "Delete vault Work?" })).toHaveTextContent("It is empty.");
  await user.click(screen.getByRole("button", { name: "Delete vault" }));
  expect(onConfirm).toHaveBeenCalledTimes(1);
  await user.click(screen.getByRole("button", { name: "Cancel" }));
  await user.keyboard("{Escape}");
  expect(onCancel).toHaveBeenCalledTimes(2);
});
