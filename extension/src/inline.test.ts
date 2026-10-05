import { beforeEach, expect, test, vi } from "vitest";
import { InlineMenu, secureHost, type MenuActions } from "./inline";

let actions: MenuActions;
let menu: InlineMenu;
let root: ShadowRoot;
let field: HTMLInputElement;

beforeEach(() => {
  // The menu attaches to <html>, which body.innerHTML does not reset.
  document.querySelectorAll("keyorra-inline").forEach((n) => n.remove());
  document.body.innerHTML = `<input id="u">`;
  field = document.getElementById("u") as HTMLInputElement;
  actions = {
    list: vi.fn().mockResolvedValue({ state: "ready", items: [{ id: "i1", title: "GitHub", username: "ivan", hasTotp: true }] }),
    fill: vi.fn().mockResolvedValue(undefined),
    unlock: vi.fn().mockResolvedValue(undefined),
    generate: vi.fn().mockResolvedValue({ state: "ready", value: "Xk9-very-long-generated-password-Qz7" }),
    useGenerated: vi.fn().mockResolvedValue(undefined),
    cards: vi.fn().mockResolvedValue({ state: "ready", items: [{ id: "c1", title: "Visa", last4: "1111" }] }),
    fillCard: vi.fn().mockResolvedValue(undefined),
    identities: vi.fn().mockResolvedValue({ state: "ready", items: [{ id: "a1", title: "Home", detail: "Ivan, Berlin" }] }),
    fillIdentity: vi.fn().mockResolvedValue(undefined),
  };
  menu = new InlineMenu(actions, { onRoot: (r) => (root = r), trusted: () => true, settleMs: 0, confirmMs: 0 });
});

const shadow = () => root;

test("focusing a field shows the icon; clicking it lists logins; picking one fills", async () => {
  menu.watch(field);
  field.dispatchEvent(new FocusEvent("focus"));
  const icon = shadow().querySelector<HTMLButtonElement>("button.icon")!;
  expect(icon.getAttribute("aria-label")).toBe("Fill with Keyorra");
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
  await vi.waitFor(() => expect(shadow().textContent).toContain("Keyorra is locked"));
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
  expect(document.querySelector("keyorra-inline")!.shadowRoot).toBeNull();
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
  document.querySelector<HTMLElement>("keyorra-inline")!.style.setProperty("opacity", "0", "important");
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
  document.querySelector("keyorra-inline")!.setAttribute("tabindex", "0");
  shadow().querySelector<HTMLButtonElement>("button.icon")!.click();
  await Promise.resolve();
  expect(actions.list).not.toHaveBeenCalled();
});

test("a transformed or blended host does nothing", async () => {
  menu.watch(field);
  field.dispatchEvent(new FocusEvent("focus"));
  const host = document.querySelector<HTMLElement>("keyorra-inline")!;
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

const openMenu = (mode: "logins" | "generator" | "cards" | "identities", m: InlineMenu = menu) => {
  m.watch(field, mode);
  field.dispatchEvent(new FocusEvent("focus"));
  shadow().querySelector<HTMLButtonElement>("button.icon")!.click();
};

test("generator mode offers a strong password and uses it", async () => {
  openMenu("generator");
  await vi.waitFor(() => expect(shadow().querySelector(".item")).not.toBeNull());
  const item = shadow().querySelector<HTMLButtonElement>(".item")!;
  expect(item.getAttribute("role")).toBe("menuitem");
  expect(item.textContent).toContain("Use a strong password");
  const value = shadow().querySelector(".generated")!.textContent!;
  expect(value).toContain("…");
  expect(value.startsWith("Xk9")).toBe(true);
  expect(value.endsWith("Qz7")).toBe(true);
  expect(actions.list).not.toHaveBeenCalled();
  item.click();
  expect(actions.useGenerated).toHaveBeenCalledWith("Xk9-very-long-generated-password-Qz7", field);
});

test("generator mode handles a locked Keyorra", async () => {
  vi.mocked(actions.generate).mockResolvedValue({ state: "locked", value: "" });
  openMenu("generator");
  await vi.waitFor(() => expect(shadow().textContent).toContain("Keyorra is locked"));
});

test("cards mode shows title and last four digits; picking fills", async () => {
  openMenu("cards");
  await vi.waitFor(() => expect(shadow().querySelector(".item")).not.toBeNull());
  expect(shadow().querySelector(".item")!.textContent).toContain("Visa");
  expect(shadow().querySelector(".item")!.textContent).toContain("•••• 1111");
  (shadow().querySelector(".item") as HTMLButtonElement).click();
  (shadow().querySelector(".item") as HTMLButtonElement).click();
  expect(actions.fillCard).toHaveBeenCalledWith("c1", field);
  expect(actions.fill).not.toHaveBeenCalled();
});

test("a card without last digits shows no mask", async () => {
  vi.mocked(actions.cards).mockResolvedValue({ state: "ready", items: [{ id: "c1", title: "Visa", last4: "" }] });
  openMenu("cards");
  await vi.waitFor(() => expect(shadow().querySelector(".item")).not.toBeNull());
  expect(shadow().querySelector(".item")!.textContent).not.toContain("•");
});

test("no cards, and the secure-page note on an insecure page", async () => {
  vi.mocked(actions.cards).mockResolvedValue({ state: "ready", items: [] });
  openMenu("cards");
  await vi.waitFor(() => expect(shadow().textContent).toMatch(/No cards in Keyorra|only filled on secure pages/));
  // jsdom runs on http://localhost:3000, which counts as secure.
  expect(shadow().textContent).toContain("No cards in Keyorra");
  vi.stubGlobal("location", { protocol: "http:", hostname: "example.com" });
  shadow().querySelector<HTMLButtonElement>("button.icon")!.click();
  await vi.waitFor(() => expect(shadow().textContent).toContain("Cards are only filled on secure pages"));
  vi.stubGlobal("location", { protocol: "https:", hostname: "example.com" });
  shadow().querySelector<HTMLButtonElement>("button.icon")!.click();
  await vi.waitFor(() => expect(shadow().textContent).toContain("No cards in Keyorra"));
  vi.unstubAllGlobals();
});

test("identities mode shows title and detail; picking fills; empty notes", async () => {
  openMenu("identities");
  await vi.waitFor(() => expect(shadow().querySelector(".item")).not.toBeNull());
  expect(shadow().querySelector(".item")!.textContent).toContain("Home");
  expect(shadow().querySelector(".item")!.textContent).toContain("Ivan, Berlin");
  (shadow().querySelector(".item") as HTMLButtonElement).click();
  (shadow().querySelector(".item") as HTMLButtonElement).click();
  expect(actions.fillIdentity).toHaveBeenCalledWith("a1", field);

  vi.mocked(actions.identities).mockResolvedValue({ state: "ready", items: [] });
  vi.stubGlobal("location", { protocol: "http:", hostname: "example.com" });
  shadow().querySelector<HTMLButtonElement>("button.icon")!.click();
  await vi.waitFor(() => expect(shadow().textContent).toContain("Addresses are only filled on secure pages"));
  vi.stubGlobal("location", { protocol: "https:", hostname: "example.com" });
  shadow().querySelector<HTMLButtonElement>("button.icon")!.click();
  await vi.waitFor(() => expect(shadow().textContent).toContain("No addresses in Keyorra"));
  vi.unstubAllGlobals();
});

test("untrusted clicks and early clicks are ignored in the new modes", async () => {
  const strict = new InlineMenu(actions, { onRoot: (r) => (root = r) });
  openMenu("cards", strict);
  await Promise.resolve();
  expect(actions.cards).not.toHaveBeenCalled();

  const quick = new InlineMenu(actions, { onRoot: (r) => (root = r), trusted: () => true, settleMs: 60_000 });
  const f2 = document.createElement("input");
  document.body.append(f2);
  quick.watch(f2, "generator");
  f2.dispatchEvent(new FocusEvent("focus"));
  shadow().querySelector<HTMLButtonElement>("button.icon")!.click();
  await vi.waitFor(() => expect(shadow().querySelector(".item")).not.toBeNull());
  (shadow().querySelector(".item") as HTMLButtonElement).click();
  expect(actions.useGenerated).not.toHaveBeenCalled();
});

test("secureHost: https, localhost, loopback and private networks are secure", () => {
  for (const hostname of ["localhost", "app.localhost", "127.0.0.1", "127.9.9.9", "[::1]", "::1", "10.0.0.1", "172.16.5.5", "172.31.5.5", "192.168.0.1", "fd12::1"]) {
    expect(secureHost({ protocol: "http:", hostname }), hostname).toBe(true);
  }
  for (const hostname of ["example.com", "203.0.113.5", "172.32.0.1", "11.0.0.1", "localhost.evil.com", "fake127.0.0.1"]) {
    expect(secureHost({ protocol: "http:", hostname }), hostname).toBe(false);
  }
  expect(secureHost({ protocol: "https:", hostname: "example.com" })).toBe(true);
});

const openAndPick = async (mode: "logins" | "cards" | "identities", m: InlineMenu) => {
  openMenu(mode, m);
  await vi.waitFor(() => expect(shadow().querySelector(".item")).not.toBeNull());
  return shadow().querySelector(".item") as HTMLButtonElement;
};

test("without visibility tracking, a card needs a second click; the first changes the label", async () => {
  const item = await openAndPick("cards", menu);
  item.click();
  expect(actions.fillCard).not.toHaveBeenCalled();
  expect(item.textContent).toContain("Click again to fill");
  item.click();
  expect(actions.fillCard).toHaveBeenCalledWith("c1", field);
});

test("the second click must come a little later, and the prompt expires after 3 s", async () => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] });
  const slow = new InlineMenu(actions, { onRoot: (r) => (root = r), trusted: () => true, settleMs: 0, confirmMs: 300 });
  const item = await openAndPick("identities", slow);
  item.click();
  vi.advanceTimersByTime(100);
  item.click(); // too soon: ignored
  expect(actions.fillIdentity).not.toHaveBeenCalled();
  vi.advanceTimersByTime(3100);
  expect(item.textContent).not.toContain("Click again");
  expect(item.textContent).toContain("Home");
  item.click(); // arms again
  expect(actions.fillIdentity).not.toHaveBeenCalled();
  vi.advanceTimersByTime(400);
  item.click();
  expect(actions.fillIdentity).toHaveBeenCalledWith("a1", field);
  vi.useRealTimers();
});

test("an untrusted second click does not confirm", async () => {
  let ok = true;
  const m = new InlineMenu(actions, { onRoot: (r) => (root = r), trusted: () => ok, settleMs: 0, confirmMs: 0 });
  const item = await openAndPick("cards", m);
  item.click();
  ok = false;
  item.click();
  expect(actions.fillCard).not.toHaveBeenCalled();
});

test("with visibility tracking one click fills a card", async () => {
  vi.stubGlobal("IntersectionObserver", class { observe() {} unobserve() {} });
  const tracked = new InlineMenu(actions, { onRoot: (r) => (root = r), trusted: () => true, settleMs: 0 });
  const item = await openAndPick("cards", tracked);
  item.click();
  expect(actions.fillCard).toHaveBeenCalledWith("c1", field);
  vi.unstubAllGlobals();
});

test("logins never need a second click", async () => {
  const item = await openAndPick("logins", menu);
  item.click();
  expect(actions.fill).toHaveBeenCalledWith("i1");
});

test("a host moved out of the place it was attached to is refused", async () => {
  const guarded = new InlineMenu(actions, { onRoot: (r) => (root = r), trusted: () => true, settleMs: 0 });
  guarded.watch(field);
  field.dispatchEvent(new FocusEvent("focus"));
  const hosts = document.querySelectorAll("keyorra-inline");
  document.body.append(hosts[hosts.length - 1]);
  shadow().querySelector<HTMLButtonElement>("button.icon")!.click();
  await Promise.resolve();
  expect(actions.list).not.toHaveBeenCalled();
});

test("watch tells whether a field is already watched", () => {
  expect(menu.isWatched(field)).toBe(false);
  menu.watch(field);
  expect(menu.isWatched(field)).toBe(true);
});
