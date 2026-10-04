import { beforeEach, expect, test } from "vitest";
import { findLoginFields } from "./detect";

function page(html: string) {
  document.body.innerHTML = html;
}

beforeEach(() => {
  document.body.innerHTML = "";
});

test("classic login form", () => {
  page(`<form><input name="q" type="search"><input id="login" name="login" type="text"><input type="password" name="password"><button>Sign in</button></form>`);
  const f = findLoginFields(document);
  expect(f.username?.id).toBe("login");
  expect(f.password?.name).toBe("password");
  expect(f.totp).toBeNull();
});

test("autocomplete hints win", () => {
  page(`<input type="text" name="a"><input type="email" autocomplete="username" name="who"><input type="password" autocomplete="current-password" name="pw">`);
  const f = findLoginFields(document);
  expect(f.username?.name).toBe("who");
  expect(f.password?.name).toBe("pw");
});

test("username-first step", () => {
  page(`<form><label for="e">Email</label><input id="e" type="email"><button>Next</button></form>`);
  const f = findLoginFields(document);
  expect(f.username?.id).toBe("e");
  expect(f.password).toBeNull();
});

test("one-time code step", () => {
  page(`<form><input name="app_otp" inputmode="numeric" maxlength="6" type="text"><button>Verify</button></form>`);
  expect(findLoginFields(document).totp?.name).toBe("app_otp");
  page(`<input autocomplete="one-time-code" name="c">`);
  expect(findLoginFields(document).totp?.name).toBe("c");
});

test("ignores hidden, disabled and sign-up password fields", () => {
  page(`<input type="password" name="h" style="display:none"><input type="password" name="d" disabled><input type="password" autocomplete="new-password" name="n">`);
  expect(findLoginFields(document).password).toBeNull();
});

test("ignores fields that are invisible by opacity or aria-hidden", () => {
  page(`<input type="password" name="o" style="opacity:0"><div aria-hidden="true"><input type="password" name="a"></div>`);
  expect(findLoginFields(document).password).toBeNull();
});

test("a search box outside the password's form is not the username", () => {
  page(`<input type="text" name="q"><form><input type="password" name="pw"></form>`);
  const f = findLoginFields(document);
  expect(f.password?.name).toBe("pw");
  expect(f.username).toBeNull();
});

test("the username comes from the password's own form first", () => {
  page(`<input type="email" name="other"><form><input type="text" name="user"><input type="password" name="pw"></form>`);
  expect(findLoginFields(document).username?.name).toBe("user");
});
