import { expect, test } from "vitest";
import { fillLogin, setValue } from "./fill";

test("setValue fires input and change", () => {
  document.body.innerHTML = `<input id="a">`;
  const input = document.getElementById("a") as HTMLInputElement;
  const seen: string[] = [];
  input.addEventListener("input", () => seen.push(`input:${input.value}`));
  input.addEventListener("change", () => seen.push(`change:${input.value}`));
  setValue(input, "ivan");
  expect(input.value).toBe("ivan");
  expect(seen).toEqual(["input:ivan", "change:ivan"]);
});

test("fillLogin fills what exists and counts it", () => {
  document.body.innerHTML = `<input id="u"><input id="p" type="password">`;
  const u = document.getElementById("u") as HTMLInputElement;
  const p = document.getElementById("p") as HTMLInputElement;
  const n = fillLogin({ username: u, password: p, totp: null }, { username: "ivan", password: "pw", totp: "123456" });
  expect(n).toBe(2);
  expect([u.value, p.value]).toEqual(["ivan", "pw"]);
});
