import { beforeEach, expect, test, vi } from "vitest";
import { InlineMenu, type MenuActions } from "./inline";

let actions: MenuActions;
let menu: InlineMenu;
let field: HTMLInputElement;

beforeEach(() => {
  // The menu attaches to <html>, which body.innerHTML does not reset.
  document.querySelectorAll("lockbox-inline").forEach((n) => n.remove());
  document.body.innerHTML = `<input id="u">`;
  field = document.getElementById("u") as HTMLInputElement;
  actions = {
    list: vi.fn().mockResolvedValue({ state: "ready", items: [{ id: "i1", title: "GitHub", username: "ivan", hasTotp: true }] }),
    fill: vi.fn().mockResolvedValue(undefined),
    unlock: vi.fn().mockResolvedValue(undefined),
  };
  menu = new InlineMenu(actions);
});

const shadow = () => document.querySelector("lockbox-inline")!.shadowRoot!;

test("focusing a field shows the icon; clicking it lists logins; picking one fills", async () => {
  menu.watch(field);
  field.dispatchEvent(new FocusEvent("focus"));
  const icon = shadow().querySelector<HTMLButtonElement>("button.icon")!;
  expect(icon.getAttribute("aria-label")).toBe("Fill with Lockbox");
  icon.click();
  await vi.waitFor(() => expect(shadow().querySelector(".item")).not.toBeNull());
  expect(shadow().querySelector(".item")!.textContent).toContain("GitHub");
  (shadow().querySelector(".item") as HTMLButtonElement).click();
  expect(actions.fill).toHaveBeenCalledWith("i1");
});

test("locked and unpaired states", async () => {
  vi.mocked(actions.list).mockResolvedValue({ state: "locked", items: [] });
  menu.watch(field);
  field.dispatchEvent(new FocusEvent("focus"));
  shadow().querySelector<HTMLButtonElement>("button.icon")!.click();
  await vi.waitFor(() => expect(shadow().textContent).toContain("Lockbox is locked"));
  shadow().querySelector<HTMLButtonElement>("button.unlock")!.click();
  expect(actions.unlock).toHaveBeenCalled();

  vi.mocked(actions.list).mockResolvedValue({ state: "unpaired", items: [] });
  shadow().querySelector<HTMLButtonElement>("button.icon")!.click();
  await vi.waitFor(() => expect(shadow().textContent).toContain("Connect this browser"));
});

test("no logins for the site", async () => {
  vi.mocked(actions.list).mockResolvedValue({ state: "ready", items: [] });
  menu.watch(field);
  field.dispatchEvent(new FocusEvent("focus"));
  shadow().querySelector<HTMLButtonElement>("button.icon")!.click();
  await vi.waitFor(() => expect(shadow().textContent).toContain("No logins for this site"));
});
