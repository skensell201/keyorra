import { beforeEach, expect, test } from "vitest";
import { findAddressFields, findCardFields, findLoginFields, findNewPasswordFields } from "./detect";

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

test("new-password: autocomplete marks, login form gives none", () => {
  page(`<form><input type="email" name="e"><input type="password" name="pw"></form>`);
  expect(findNewPasswordFields(document)).toEqual([]);
  page(`<form><input type="password" autocomplete="new-password" name="n"><input type="password" name="x"></form>`);
  expect(findNewPasswordFields(document).map((i) => i.name)).toEqual(["n"]);
});

test("new-password: change-password and sign-up forms", () => {
  page(`<form><input type="password" name="cur" autocomplete="current-password"><input type="password" name="new"><input type="password" name="conf"></form>`);
  expect(findNewPasswordFields(document).map((i) => i.name)).toEqual(["new", "conf"]);
  // Two fields: password and confirmation, both new.
  page(`<form><input type="password" name="pw"><input type="password" name="conf"></form>`);
  expect(findNewPasswordFields(document).map((i) => i.name)).toEqual(["pw", "conf"]);
});

test("new-password: two fields where the first asks for the current or old password", () => {
  for (const first of [`name="current_pw"`, `id="old"`, `autocomplete="current-password" name="a"`, `placeholder="Existing password" name="a"`]) {
    page(`<form><input type="password" ${first}><input type="password" name="new"></form>`);
    expect(findNewPasswordFields(document).map((i) => i.name)).toEqual(["new"]);
  }
});

test("new-password: hidden fields are ignored", () => {
  page(`<form><input type="password" name="a"><input type="password" name="b" style="display:none"></form>`);
  expect(findNewPasswordFields(document)).toEqual([]);
});

test("card: Stripe-like form by autocomplete", () => {
  page(`<form><input autocomplete="cc-name" name="n"><input autocomplete="cc-number" name="cardnumber"><input autocomplete="cc-exp" name="exp-date"><input autocomplete="cc-csc" name="cvc"></form>`);
  const c = findCardFields(document);
  expect([c.number?.getAttribute("name"), c.name?.getAttribute("name"), c.exp?.getAttribute("name"), c.cvc?.getAttribute("name")]).toEqual(["cardnumber", "n", "exp-date", "cvc"]);
  expect(c.expMonth).toBeNull();
});

test("card: hints and month/year selects", () => {
  page(`<form><input name="card_number"><input name="cardholder"><select name="exp_month"></select><select name="exp_year"></select><input name="cvv"></form>`);
  const c = findCardFields(document);
  expect(c.number?.getAttribute("name")).toBe("card_number");
  expect(c.name?.getAttribute("name")).toBe("cardholder");
  expect(c.expMonth?.tagName).toBe("SELECT");
  expect(c.expYear?.getAttribute("name")).toBe("exp_year");
  expect(c.cvc?.getAttribute("name")).toBe("cvv");
  expect(c.exp).toBeNull();
});

test("card: needs a number field; invisible card fields are skipped", () => {
  page(`<form><input name="cvv"><input name="cardholder"></form>`);
  expect(findCardFields(document).cvc).toBeNull();
  page(`<form><input name="cardnumber" style="display:none"><input name="cvv"></form>`);
  expect(findCardFields(document).number).toBeNull();
});

test("card: a sign-in form has no card fields", () => {
  page(`<form><input type="email" name="email"><input type="password" name="password"></form>`);
  const c = findCardFields(document);
  expect(Object.values(c).every((v) => v === null)).toBe(true);
});

test("address: autocomplete fields", () => {
  page(`<form><input autocomplete="given-name" name="a"><input autocomplete="family-name" name="b"><input autocomplete="email" name="c"><input autocomplete="tel" name="d"><input autocomplete="address-line1" name="e"><input autocomplete="address-level2" name="f"><input autocomplete="postal-code" name="g"><select autocomplete="country" name="h"></select></form>`);
  const a = findAddressFields(document);
  const names = Object.values(a).map((f) => f?.getAttribute("name") ?? null);
  expect(names).toEqual(["a", "b", null, "c", "d", "e", "f", "g", "h"]);
});

test("address: hints", () => {
  page(`<form><input name="full_name"><input name="city"><input name="zip"><input name="street"></form>`);
  const a = findAddressFields(document);
  expect(a.name?.getAttribute("name")).toBe("full_name");
  expect(a.city?.getAttribute("name")).toBe("city");
  expect(a.postalCode?.getAttribute("name")).toBe("zip");
  expect(a.street?.getAttribute("name")).toBe("street");
});

test("address: a sign-in form gives nothing, email alone is not an address", () => {
  page(`<form><input type="email" name="email" autocomplete="email"><input type="password" name="password"></form>`);
  expect(Object.values(findAddressFields(document)).every((v) => v === null)).toBe(true);
  page(`<form><input name="email" type="email"><input name="phone" type="tel"><input name="city"></form>`);
  expect(Object.values(findAddressFields(document)).every((v) => v === null)).toBe(true);
});

test("address: a card form is not an address", () => {
  page(`<form><input autocomplete="cc-name" name="name_on_card"><input autocomplete="cc-number" name="cardnumber"></form>`);
  expect(Object.values(findAddressFields(document)).every((v) => v === null)).toBe(true);
});

// ---- plausibility of card and address fields ----

function layout(el: Element, rect: Partial<DOMRect>) {
  const r = { left: 0, top: 0, right: 0, bottom: 0, width: 0, height: 0, x: 0, y: 0, ...rect };
  el.getBoundingClientRect = () => r as DOMRect;
}

const CARD_FORM = `<form><input autocomplete="cc-number" name="n"><input autocomplete="cc-csc" name="c" type="password"><input autocomplete="cc-name" name="h"></form>`;

test("card: a masked CVC is accepted, other card fields never are password inputs", () => {
  page(`<form><input autocomplete="cc-number" name="n"><input autocomplete="cc-csc" name="c" type="password"><input autocomplete="cc-name" name="h" type="password"><input autocomplete="cc-exp" name="e" type="password"></form>`);
  const c = findCardFields(document);
  expect(c.cvc?.getAttribute("name")).toBe("c");
  expect(c.name).toBeNull();
  expect(c.exp).toBeNull();
});

test("card and address: tiny, faded and off-document fields are ignored", () => {
  page(CARD_FORM);
  const inputs = Array.from(document.querySelectorAll("input"));
  document.documentElement.getBoundingClientRect = () => ({ width: 1000, height: 800, left: 0, top: 0, right: 1000, bottom: 800 }) as DOMRect;
  for (const i of inputs) layout(i, { left: 10, top: 10, right: 210, bottom: 40, width: 200, height: 30 });
  expect(findCardFields(document).number?.getAttribute("name")).toBe("n");
  layout(inputs[0], { left: 10, top: 10, right: 12, bottom: 12, width: 2, height: 2 });
  expect(findCardFields(document).number).toBeNull();
  layout(inputs[0], { left: -500, top: 10, right: -300, bottom: 40, width: 200, height: 30 });
  expect(findCardFields(document).number).toBeNull();
  layout(inputs[0], { left: 10, top: -90, right: 210, bottom: -60, width: 200, height: 30 });
  expect(findCardFields(document).number).toBeNull();
  layout(inputs[0], { left: 10, top: 10, right: 210, bottom: 40, width: 200, height: 30 });
  inputs[0].style.opacity = "0.05";
  expect(findCardFields(document).number).toBeNull();
  inputs[0].style.opacity = "";
  (inputs[0].parentElement as HTMLElement).style.opacity = "0.05";
  expect(findCardFields(document).number).toBeNull();
  delete (document.documentElement as any).getBoundingClientRect;
});

test("address: tiny or faded fields are ignored", () => {
  page(`<form><input autocomplete="given-name" name="a"><input autocomplete="family-name" name="b" style="opacity:0.05"></form>`);
  expect(Object.values(findAddressFields(document)).every((v) => v === null)).toBe(true);
});
