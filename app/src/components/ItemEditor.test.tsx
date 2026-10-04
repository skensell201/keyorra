import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { api, type Item } from "../api";
import { loginItem } from "../test/fixtures";
import { ItemEditor } from "./ItemEditor";

vi.mock("../api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api")>();
  return { ...actual, api: { ...actual.api, saveItem: vi.fn(), generate: vi.fn() } };
});

beforeEach(() => {
  vi.mocked(api.saveItem).mockReset().mockImplementation(async (item: Item) => item);
  vi.mocked(api.generate).mockReset().mockResolvedValue("Gen-123");
});

const saved = () => vi.mocked(api.saveItem).mock.lastCall![0];

test("edits basic fields and keeps everything else", async () => {
  const user = userEvent.setup();
  const onSave = vi.fn();
  render(<ItemEditor isNew={false} item={loginItem()} onSave={onSave} onCancel={vi.fn()} />);

  await user.clear(screen.getByLabelText("Title"));
  await user.type(screen.getByLabelText("Title"), "GitHub work");
  await user.clear(screen.getByLabelText("Password"));
  await user.type(screen.getByLabelText("Password"), "new-pass");
  await user.clear(screen.getByLabelText("Websites"));
  await user.type(screen.getByLabelText("Websites"), "https://github.com{Enter}https://gist.github.com");
  await user.clear(screen.getByLabelText("Tags"));
  await user.type(screen.getByLabelText("Tags"), "dev, work");
  await user.click(screen.getByLabelText("Favorite"));
  await user.click(screen.getByRole("button", { name: "Save" }));

  expect(saved().title).toBe("GitHub work");
  expect(saved().fields[1].value).toEqual({ type: "concealed", value: "new-pass" });
  expect(saved().fields[0].value).toEqual({ type: "text", value: "ivan" });
  expect(saved().urls).toEqual(["https://github.com", "https://gist.github.com"]);
  expect(saved().tags).toEqual(["dev", "work"]);
  expect(saved().favorite).toBe(true);
  expect(saved().sections).toEqual(loginItem().sections);
  await waitFor(() => expect(onSave).toHaveBeenCalled());
});

test("shows a save error", async () => {
  const user = userEvent.setup();
  vi.mocked(api.saveItem).mockRejectedValue({ kind: "invalid", message: "Title is required" });
  render(<ItemEditor isNew={false} item={loginItem({ title: "" })} onSave={vi.fn()} onCancel={vi.fn()} />);
  await user.click(screen.getByRole("button", { name: "Save" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Title is required");
});

test("the generator fills the password", async () => {
  const user = userEvent.setup();
  render(<ItemEditor isNew={false} item={loginItem()} onSave={vi.fn()} onCancel={vi.fn()} />);
  await user.click(screen.getByRole("button", { name: "Generate" }));
  await screen.findByText("Gen-123");
  await user.click(screen.getByRole("button", { name: "Use" }));
  expect(screen.getByLabelText("Password")).toHaveValue("Gen-123");
});

test("cancel", async () => {
  const user = userEvent.setup();
  const onCancel = vi.fn();
  render(<ItemEditor isNew={false} item={loginItem()} onSave={vi.fn()} onCancel={onCancel} />);
  await user.click(screen.getByRole("button", { name: "Cancel" }));
  expect(onCancel).toHaveBeenCalled();
});

test("adds a one-time password secret", async () => {
  const user = userEvent.setup();
  render(<ItemEditor item={loginItem({ sections: [] })} isNew={false} onSave={vi.fn()} onCancel={vi.fn()} />);
  await user.click(screen.getByRole("button", { name: "Add one-time password" }));
  await user.type(screen.getByLabelText("Value of field 1"), "JBSWY3DPEHPK3PXP");
  await user.click(screen.getByRole("button", { name: "Save" }));
  const otp = saved().fields.find((f) => f.value.type === "totp");
  expect(otp).toMatchObject({ label: "one-time password", value: { type: "totp", value: "JBSWY3DPEHPK3PXP" } });
  expect(otp!.id).toMatch(/^otp-/);
});

test("edits, retypes, relabels and removes template fields", async () => {
  const user = userEvent.setup();
  const card = loginItem({
    kind: "credit_card",
    sections: [],
    fields: [
      { id: "cardholder", label: "cardholder name", value: { type: "text", value: "" } },
      { id: "number", label: "number", value: { type: "concealed", value: "" } },
      { id: "cvv", label: "verification number", value: { type: "concealed", value: "" } },
    ],
  });
  render(<ItemEditor item={card} isNew onSave={vi.fn()} onCancel={vi.fn()} />);
  await user.type(screen.getByLabelText("Value of field 2"), "4111111111111111");
  await user.selectOptions(screen.getByLabelText("Type of field 1"), "concealed");
  await user.clear(screen.getByLabelText("Label of field 1"));
  await user.type(screen.getByLabelText("Label of field 1"), "owner");
  await user.click(screen.getByRole("button", { name: "Remove field 3" }));
  await user.click(screen.getByRole("button", { name: "Save" }));
  expect(saved().fields).toEqual([
    { id: "cardholder", label: "owner", value: { type: "concealed", value: "" } },
    { id: "number", label: "number", value: { type: "concealed", value: "4111111111111111" } },
  ]);
});

test("adds a plain field", async () => {
  const user = userEvent.setup();
  render(<ItemEditor item={loginItem({ sections: [] })} isNew={false} onSave={vi.fn()} onCancel={vi.fn()} />);
  await user.click(screen.getByRole("button", { name: "Add field" }));
  await user.type(screen.getByLabelText("Value of field 1"), "PIN 1234");
  await user.click(screen.getByRole("button", { name: "Save" }));
  expect(saved().fields[2]).toMatchObject({ label: "", value: { type: "text", value: "PIN 1234" } });
});

test("hidden values stay masked until the shared toggle reveals them", async () => {
  const user = userEvent.setup();
  const item = loginItem({
    sections: [],
    fields: [
      ...loginItem().fields,
      { id: "pin", label: "PIN", value: { type: "concealed", value: "1234" } },
      { id: "otp-1", label: "one-time password", value: { type: "totp", value: "JBSWY3DPEHPK3PXP" } },
    ],
  });
  render(<ItemEditor item={item} isNew={false} onSave={vi.fn()} onCancel={vi.fn()} />);
  expect(screen.getByLabelText("Value of field 1")).toHaveAttribute("type", "password");
  expect(screen.getByLabelText("Value of field 2")).toHaveAttribute("type", "password");
  await user.click(screen.getByRole("button", { name: "Show hidden values" }));
  expect(screen.getByLabelText("Value of field 1")).toHaveAttribute("type", "text");
  expect(screen.getByLabelText("Value of field 2")).toHaveAttribute("type", "text");
  await user.click(screen.getByRole("button", { name: "Hide hidden values" }));
  expect(screen.getByLabelText("Value of field 1")).toHaveAttribute("type", "password");
});

test("a month/year field is shown read-only and saved unchanged", async () => {
  const user = userEvent.setup();
  const expiry = { id: "expiry", label: "expiry date", value: { type: "month_year", value: 202712 } } as const;
  render(
    <ItemEditor item={loginItem({ sections: [], fields: [...loginItem().fields, expiry] })} isNew={false} onSave={vi.fn()} onCancel={vi.fn()} />,
  );
  expect(screen.getByText("12/2027")).toBeInTheDocument();
  expect(screen.queryByLabelText("Type of field 1")).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Save" }));
  expect(saved().fields[2]).toEqual(expiry);
});
