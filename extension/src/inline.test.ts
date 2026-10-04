import { beforeEach, expect, test, vi } from "vitest";
import { InlineMenu, type MenuActions } from "./inline";

let actions: MenuActions;
let menu: InlineMenu;
let root: ShadowRoot;
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
  menu = new InlineMenu(actions, { onRoot: (r) => (root = r), trusted: () => true, settleMs: 0 });
});

const shadow = () => root;

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

test("the shadow root is closed to the page", () => {
  expect(document.querySelector("lockbox-inline")!.shadowRoot).toBeNull();
});

test("untrusted (script-made) clicks do nothing", async () => {
  const strict = new InlineMenu(actions, { onRoot: (r) => (root = r) });
  strict.watch(field);
  field.dispatchEvent(new FocusEvent("focus"));
  shadow().querySelector<HTMLButtonElement>("button.icon")!.click();
  await Promise.resolve();
  expect(actions.list).not.toHaveBeenCalled();
});

test("a click on a hidden host does nothing", async () => {
  menu.watch(field);
  field.dispatchEvent(new FocusEvent("focus"));
  document.querySelector<HTMLElement>("lockbox-inline")!.style.setProperty("opacity", "0", "important");
  shadow().querySelector<HTMLButtonElement>("button.icon")!.click();
  await Promise.resolve();
  expect(actions.list).not.toHaveBeenCalled();
});

test("item clicks right after the panel opens are ignored", async () => {
  const quick = new InlineMenu(actions, { onRoot: (r) => (root = r), trusted: () => true, settleMs: 60_000 });
  quick.watch(field);
  field.dispatchEvent(new FocusEvent("focus"));
  shadow().querySelector<HTMLButtonElement>("button.icon")!.click();
  await vi.waitFor(() => expect(shadow().querySelector(".item")).not.toBeNull());
  (shadow().querySelector(".item") as HTMLButtonElement).click();
  expect(actions.fill).not.toHaveBeenCalled();
});

test("a failing list shows a reload hint; Escape closes the panel", async () => {
  vi.mocked(actions.list).mockRejectedValue(new Error("Extension context invalidated"));
  menu.watch(field);
  field.dispatchEvent(new FocusEvent("focus"));
  shadow().querySelector<HTMLButtonElement>("button.icon")!.click();
  await vi.waitFor(() => expect(shadow().textContent).toContain("reload the page"));
  document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" }));
  expect(shadow().querySelector(".panel")).toBeNull();
});

test("a host with a tabindex does nothing", async () => {
  menu.watch(field);
  field.dispatchEvent(new FocusEvent("focus"));
  document.querySelector("lockbox-inline")!.setAttribute("tabindex", "0");
  shadow().querySelector<HTMLButtonElement>("button.icon")!.click();
  await Promise.resolve();
  expect(actions.list).not.toHaveBeenCalled();
});

test("a transformed or blended host does nothing", async () => {
  menu.watch(field);
  field.dispatchEvent(new FocusEvent("focus"));
  const host = document.querySelector<HTMLElement>("lockbox-inline")!;
  host.style.setProperty("mix-blend-mode", "difference", "important");
  shadow().querySelector<HTMLButtonElement>("button.icon")!.click();
  await Promise.resolve();
  expect(actions.list).not.toHaveBeenCalled();
});

test("an inverting page filter (dark mode extensions) is allowed", async () => {
  menu.watch(field);
  field.dispatchEvent(new FocusEvent("focus"));
  document.documentElement.style.filter = "invert(1) hue-rotate(180deg)";
  shadow().querySelector<HTMLButtonElement>("button.icon")!.click();
  await vi.waitFor(() => expect(actions.list).toHaveBeenCalled());
  document.documentElement.style.filter = "";
});

test("an obscured element reported by IntersectionObserver is refused", async () => {
  let report: (entries: any[]) => void = () => {};
  vi.stubGlobal("IntersectionObserver", class { constructor(cb: any) { report = cb; } observe() {} unobserve() {} });
  const watchful = new InlineMenu(actions, { onRoot: (r) => (root = r), trusted: () => true, settleMs: 0 });
  watchful.watch(field);
  field.dispatchEvent(new FocusEvent("focus"));
  const icon = shadow().querySelector<HTMLButtonElement>("button.icon")!;
  report([{ target: icon, isVisible: false }]);
  icon.click();
  await Promise.resolve();
  expect(actions.list).not.toHaveBeenCalled();
  report([{ target: icon, isVisible: true }]);
  icon.click();
  await vi.waitFor(() => expect(actions.list).toHaveBeenCalled());
  vi.unstubAllGlobals();
});

test("a field that is already focused when watched shows the icon", () => {
  field.focus();
  menu.watch(field);
  expect(shadow().querySelector<HTMLButtonElement>("button.icon")!.hidden).toBe(false);
});
