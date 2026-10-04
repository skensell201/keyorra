import { beforeEach, expect, test } from "vitest";
import { fillAddress, fillCard, fillLogin, fillNewPassword, setValue } from "./fill";
import { findAddressFields, findCardFields } from "./detect";

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

beforeEach(() => {
  document.body.innerHTML = "";
});

const CARD = { name: "Ivan Kostin", number: "4111111111111111", expMonth: "12", expYear: "2027", cvc: "123" };
const ID = { givenName: "Ivan", familyName: "Kostin", email: "i@x.io", phone: "+1 555", street: "1 Main St", city: "Paris", postalCode: "75001", country: "France" };
const val = (name: string) => (document.querySelector(`[name="${name}"]`) as HTMLInputElement).value;

test("fillCard: single expiry field gets MM/YY, long forms MM/YYYY", () => {
  document.body.innerHTML = `<input autocomplete="cc-number" name="n"><input autocomplete="cc-name" name="nm"><input autocomplete="cc-exp" name="e"><input autocomplete="cc-csc" name="c">`;
  fillCard(findCardFields(document), CARD);
  expect([val("n"), val("nm"), val("e"), val("c")]).toEqual([CARD.number, CARD.name, "12/27", "123"]);
  document.body.innerHTML = `<input autocomplete="cc-number" name="n"><input autocomplete="cc-exp" name="e" placeholder="MM/YYYY">`;
  fillCard(findCardFields(document), CARD);
  expect(val("e")).toBe("12/2027");
  document.body.innerHTML = `<input autocomplete="cc-number" name="n"><input autocomplete="cc-exp" name="e" maxlength="7">`;
  fillCard(findCardFields(document), CARD);
  expect(val("e")).toBe("12/2027");
});

test("fillCard: selects match by value or text and fire events", () => {
  document.body.innerHTML = `<input autocomplete="cc-number" name="n"><select name="exp_month"><option value="">Month</option><option value="11">11 - November</option><option value="12">12 - December</option></select><select name="exp_year"><option>2026</option><option value="27">2027</option></select>`;
  const seen: string[] = [];
  for (const s of document.querySelectorAll("select")) for (const t of ["input", "change"]) s.addEventListener(t, () => seen.push(`${s.name}:${t}`));
  fillCard(findCardFields(document), CARD);
  expect(val("exp_month")).toBe("12");
  expect(val("exp_year")).toBe("27");
  expect(seen).toEqual(["exp_month:input", "exp_month:change", "exp_year:input", "exp_year:change"]);
});

test("fillCard: month matches text starting with two digits; no match leaves select alone", () => {
  document.body.innerHTML = `<input autocomplete="cc-number" name="n"><select name="exp_month"><option value="dec">12 - Dec</option><option value="jan">01 - Jan</option></select><select name="exp_year"><option value="a">2030</option></select>`;
  fillCard(findCardFields(document), CARD);
  expect(val("exp_month")).toBe("dec");
  expect(val("exp_year")).toBe("a");
});

test("fillCard: keeps an existing cardholder name, skips unusable fields", () => {
  document.body.innerHTML = `<input autocomplete="cc-number" name="n"><input autocomplete="cc-name" name="nm" value="Kept"><input autocomplete="cc-csc" name="c" style="display:none">`;
  fillCard(findCardFields(document), CARD);
  expect([val("n"), val("nm"), val("c")]).toEqual([CARD.number, "Kept", ""]);
});

test("fillAddress: split names, empty-only, country select", () => {
  document.body.innerHTML = `<input autocomplete="given-name" name="g"><input autocomplete="family-name" name="f" value="Keep"><input autocomplete="email" name="e"><input autocomplete="tel" name="t"><input autocomplete="address-line1" name="s"><input autocomplete="address-level2" name="c"><input autocomplete="postal-code" name="z"><select autocomplete="country" name="k"><option value="DE">Germany</option><option value="FR">France</option></select>`;
  fillAddress(findAddressFields(document), ID);
  expect([val("g"), val("f"), val("e"), val("t"), val("s"), val("c"), val("z"), val("k")]).toEqual(["Ivan", "Keep", "i@x.io", "+1 555", "1 Main St", "Paris", "75001", "FR"]);
});

test("fillAddress: a lone name field gets given + family", () => {
  document.body.innerHTML = `<input autocomplete="name" name="n"><input autocomplete="address-level2" name="c">`;
  fillAddress(findAddressFields(document), ID);
  expect([val("n"), val("c")]).toEqual(["Ivan Kostin", "Paris"]);
});

test("fillNewPassword fills every field via setValue", () => {
  document.body.innerHTML = `<input type="password" name="a"><input type="password" name="b">`;
  const seen: string[] = [];
  const [a, b] = Array.from(document.querySelectorAll("input"));
  a.addEventListener("input", () => seen.push("a"));
  expect(fillNewPassword([a, b], "S3cret!")).toBe(2);
  expect([a.value, b.value, seen]).toEqual(["S3cret!", "S3cret!", ["a"]]);
});
