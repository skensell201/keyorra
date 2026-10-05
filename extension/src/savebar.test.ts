import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { SaveBar, type SaveBarActions } from "./savebar";

let actions: SaveBarActions;
let bar: SaveBar;
let root: ShadowRoot;
let trusted = true;
let visible = true;

beforeEach(() => {
  vi.useFakeTimers();
  trusted = true;
  visible = true;
  document.querySelectorAll("keepsake-savebar").forEach((n) => n.remove());
  actions = { save: vi.fn().mockResolvedValue(undefined), dismiss: vi.fn() };
  bar = new SaveBar(actions, { onRoot: (r) => (root = r), trusted: () => trusted, visible: () => visible, settleMs: 0 });
});

afterEach(() => {
  vi.useRealTimers();
});

const btn = (label: string) => Array.from(root.querySelectorAll("button")).find((b) => b.textContent === label)!;

test("a new login shows the host, the username and Save / Not now", () => {
  bar.show({ username: "ivan", status: "new" });
  expect(root.textContent).toContain(`Save login for ${location.host}?`);
  expect(root.textContent).toContain("ivan");
  expect(btn("Save")).toBeTruthy();
  expect(btn("Not now")).toBeTruthy();
});

test("a changed password offers Update", () => {
  bar.show({ username: "ivan", status: "changed" });
  expect(root.textContent).toContain(`Update password for ${location.host}?`);
  expect(btn("Update")).toBeTruthy();
  expect(root.textContent).not.toContain("Save login");
});

test("Save calls save, shows Saved for 2 s, then hides", async () => {
  bar.show({ username: "ivan", status: "new" });
  btn("Save").click();
  await vi.advanceTimersByTimeAsync(0);
  expect(actions.save).toHaveBeenCalled();
  expect(root.textContent).toContain("Saved");
  await vi.advanceTimersByTimeAsync(2100);
  expect(root.querySelector(".bar")).toBeNull();
});

test("a failed save says so instead of Saved", async () => {
  vi.mocked(actions.save).mockRejectedValue(new Error("x"));
  bar.show({ username: "ivan", status: "new" });
  btn("Save").click();
  await vi.advanceTimersByTimeAsync(0);
  expect(root.textContent).toContain("Couldn't save");
  expect(root.textContent).not.toContain("Saved");
});

test("Not now dismisses", () => {
  bar.show({ username: "ivan", status: "new" });
  btn("Not now").click();
  expect(actions.dismiss).toHaveBeenCalled();
  expect(root.querySelector(".bar")).toBeNull();
});

test("untrusted and hidden clicks do nothing", () => {
  bar.show({ username: "ivan", status: "new" });
  trusted = false;
  btn("Save").click();
  btn("Not now").click();
  trusted = true;
  visible = false;
  btn("Save").click();
  expect(actions.save).not.toHaveBeenCalled();
  expect(actions.dismiss).not.toHaveBeenCalled();
});

test("clicks inside the settle time are ignored", () => {
  bar = new SaveBar(actions, { onRoot: (r) => (root = r), trusted: () => true, visible: () => true, settleMs: 300 });
  bar.show({ username: "ivan", status: "new" });
  btn("Save").click();
  expect(actions.save).not.toHaveBeenCalled();
  vi.advanceTimersByTime(350);
  btn("Save").click();
  expect(actions.save).toHaveBeenCalled();
});

test("the bar hides itself after 30 s", () => {
  bar.show({ username: "ivan", status: "new" });
  vi.advanceTimersByTime(29000);
  expect(root.querySelector(".bar")).not.toBeNull();
  vi.advanceTimersByTime(1500);
  expect(root.querySelector(".bar")).toBeNull();
});

test("page-controlled text is never parsed as HTML; the root is closed", () => {
  bar.show({ username: `<img src=x onerror=alert(1)>`, status: "new" });
  expect(root.querySelector("img")).toBeNull();
  expect(root.textContent).toContain("<img");
  expect(document.querySelector("keepsake-savebar")!.shadowRoot).toBeNull();
});

test("the host is in the page only while the bar is shown", () => {
  expect(document.querySelector("keepsake-savebar")).toBeNull();
  bar.show({ username: "ivan", status: "new" });
  expect(document.querySelector("keepsake-savebar")).not.toBeNull();
  bar.hide();
  expect(document.querySelector("keepsake-savebar")).toBeNull();
  bar.show({ username: "ivan", status: "new" });
  btn("Not now").click();
  expect(document.querySelector("keepsake-savebar")).toBeNull();
});

test("the bar is an alert dialog labelled by its message", () => {
  bar.show({ username: "ivan", status: "new" });
  const el = root.querySelector(".bar")!;
  expect(el.getAttribute("role")).toBe("alertdialog");
  const label = root.getElementById?.(el.getAttribute("aria-labelledby")!) ?? root.querySelector(`#${el.getAttribute("aria-labelledby")}`);
  expect(label?.textContent).toContain("Save login for");
});

test("Escape dismisses, but only a trusted one and only while shown", () => {
  const esc = () => document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" }));
  esc();
  expect(actions.dismiss).not.toHaveBeenCalled();
  bar.show({ username: "ivan", status: "new" });
  trusted = false;
  esc();
  expect(root.querySelector(".bar")).not.toBeNull();
  trusted = true;
  esc();
  expect(actions.dismiss).toHaveBeenCalledTimes(1);
  expect(root.querySelector(".bar")).toBeNull();
  esc();
  expect(actions.dismiss).toHaveBeenCalledTimes(1);
});

test("hovering or focusing the bar pauses the auto-hide", () => {
  bar.show({ username: "ivan", status: "new" });
  const el = root.querySelector(".bar")!;
  vi.advanceTimersByTime(20_000);
  el.dispatchEvent(new MouseEvent("mouseenter"));
  vi.advanceTimersByTime(60_000);
  expect(root.querySelector(".bar")).not.toBeNull();
  el.dispatchEvent(new MouseEvent("mouseleave"));
  vi.advanceTimersByTime(29_000);
  expect(root.querySelector(".bar")).not.toBeNull();
  vi.advanceTimersByTime(1_500);
  expect(root.querySelector(".bar")).toBeNull();

  bar.show({ username: "ivan", status: "new" });
  const again = root.querySelector(".bar")!;
  again.dispatchEvent(new FocusEvent("focusin"));
  vi.advanceTimersByTime(60_000);
  expect(root.querySelector(".bar")).not.toBeNull();
  again.dispatchEvent(new FocusEvent("focusout"));
  vi.advanceTimersByTime(30_500);
  expect(root.querySelector(".bar")).toBeNull();
});

test("a host moved away from <html> is refused by the default visibility check", () => {
  const real = new SaveBar(actions, { onRoot: (r) => (root = r), trusted: () => true, settleMs: 0 });
  real.show({ username: "ivan", status: "new" });
  const host = document.querySelector("keepsake-savebar")!;
  document.body.append(host);
  btn("Save").click();
  expect(actions.save).not.toHaveBeenCalled();
  document.documentElement.append(host);
  btn("Save").click();
  expect(actions.save).toHaveBeenCalled();
});
