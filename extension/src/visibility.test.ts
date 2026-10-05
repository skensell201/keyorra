import { beforeEach, expect, test } from "vitest";
import { defaultVisible } from "./visibility";

let host: HTMLElement;
let target: HTMLElement;

beforeEach(() => {
  document.documentElement.removeAttribute("style");
  document.body.removeAttribute("style");
  document.body.innerHTML = `<div id="wrap"><keepsake-test><button>x</button></keepsake-test></div>`;
  host = document.querySelector("keepsake-test") as HTMLElement;
  target = host.querySelector("button") as HTMLElement;
});

const ok = (parent?: Node | null) => defaultVisible(new MouseEvent("click"), host, target, parent);
const wrap = () => document.getElementById("wrap") as HTMLElement;

test("a plain host passes, with or without an expected parent", () => {
  expect(ok()).toBe(true);
  expect(ok(wrap())).toBe(true);
});

test("a host moved away from the parent it was attached to is refused", () => {
  expect(ok(document.documentElement)).toBe(false);
  document.body.append(host);
  expect(ok(wrap())).toBe(false);
  expect(ok(document.body)).toBe(true);
});

test("every ancestor is checked, not only the host and <html>", () => {
  for (const [prop, value] of [
    ["opacity", "0.5"],
    ["filter", "opacity(0.2)"],
    ["mask-image", "linear-gradient(black, transparent)"],
    ["clip-path", "inset(0 90% 0 0)"],
    ["mix-blend-mode", "difference"],
    ["transform", "translateX(500px)"],
  ]) {
    wrap().style.setProperty(prop, value);
    expect(ok(), prop).toBe(false);
    wrap().style.removeProperty(prop);
    expect(ok(), `${prop} removed`).toBe(true);
  }
});

test("<body> and <html> are ancestors too, and an inverting filter is still fine", () => {
  document.body.style.opacity = "0.3";
  expect(ok()).toBe(false);
  document.body.style.opacity = "";
  document.documentElement.style.transform = "scale(0.1)";
  expect(ok()).toBe(false);
  document.documentElement.style.transform = "";
  wrap().style.filter = "invert(1) hue-rotate(180deg)";
  expect(ok()).toBe(true);
});
