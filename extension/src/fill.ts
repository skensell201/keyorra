import type { LoginFields, CardFields, AddressFields, Field } from "./detect";
import type { Credentials, CardFill, IdentityFill } from "./client";

/** Sets a value the way a user would, so frameworks (React, Vue) notice it. */
export function setValue(input: HTMLInputElement, value: string): void {
  input.focus();
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
  if (setter) setter.call(input, value);
  else input.value = value;
  input.dispatchEvent(new Event("input", { bubbles: true }));
  input.dispatchEvent(new Event("change", { bubbles: true }));
}

export function fillLogin(fields: LoginFields, creds: Credentials): number {
  let filled = 0;
  if (fields.username && creds.username) {
    setValue(fields.username, creds.username);
    filled++;
  }
  if (fields.password && creds.password) {
    setValue(fields.password, creds.password);
    filled++;
  }
  if (fields.totp && creds.totp) {
    setValue(fields.totp, creds.totp);
    filled++;
  }
  return filled;
}

/** Picks the option whose value or text satisfies `match`, then fires input and change. */
function setSelect(select: HTMLSelectElement, match: (value: string, text: string) => boolean): boolean {
  const option = Array.from(select.options).find((o) => match(o.value.trim(), o.text.trim()));
  if (!option) return false;
  select.focus();
  select.value = option.value;
  select.dispatchEvent(new Event("input", { bubbles: true }));
  select.dispatchEvent(new Event("change", { bubbles: true }));
  return true;
}

function put(field: Field, value: string, match: (value: string, text: string) => boolean = (v, t) => v === value || t === value): boolean {
  if (field instanceof HTMLSelectElement) return setSelect(field, match);
  setValue(field, value);
  return true;
}

export function fillNewPassword(fields: HTMLInputElement[], password: string): number {
  for (const f of fields) setValue(f, password);
  return fields.length;
}

export function fillCard(fields: CardFields, card: CardFill): number {
  let filled = 0;
  const month = card.expMonth.replace(/\D/g, "").padStart(2, "0").slice(-2);
  const yy = card.expYear.replace(/\D/g, "").slice(-2);
  const yyyy = card.expYear.replace(/\D/g, "").length === 4 ? card.expYear.replace(/\D/g, "") : `20${yy}`;
  const count = (ok: boolean) => {
    if (ok) filled++;
  };
  if (fields.number && card.number) count(put(fields.number, card.number));
  if (fields.name && card.name && !fields.name.value) count(put(fields.name, card.name));
  if (fields.exp && isInputField(fields.exp)) {
    const long = fields.exp.maxLength >= 7 || /yyyy/i.test(fields.exp.placeholder);
    setValue(fields.exp, `${month}/${long ? yyyy : yy}`);
    filled++;
  }
  if (fields.expMonth) {
    count(put(fields.expMonth, month, (v, t) => v === month || t === month || v === String(Number(month)) || t === String(Number(month)) || t.startsWith(month)));
  }
  if (fields.expYear) {
    const short = isInputField(fields.expYear) && (fields.expYear.maxLength === 2 || /^yy$/i.test(fields.expYear.placeholder));
    count(put(fields.expYear, short ? yy : yyyy, (v, t) => v === yyyy || v === yy || t === yyyy || t === yy));
  }
  if (fields.cvc && card.cvc) count(put(fields.cvc, card.cvc));
  return filled;
}

function isInputField(f: Field): f is HTMLInputElement {
  return f instanceof HTMLInputElement;
}

export function fillAddress(fields: AddressFields, identity: IdentityFill): number {
  let filled = 0;
  const fillEmpty = (field: Field | null, value: string, match?: (v: string, t: string) => boolean) => {
    if (!field || !value || (isInputField(field) && field.value)) return;
    if (put(field, value, match)) filled++;
  };
  fillEmpty(fields.givenName, identity.givenName);
  fillEmpty(fields.familyName, identity.familyName);
  if (!fields.givenName && !fields.familyName) {
    fillEmpty(fields.name, `${identity.givenName} ${identity.familyName}`.trim());
  }
  fillEmpty(fields.email, identity.email);
  fillEmpty(fields.phone, identity.phone);
  fillEmpty(fields.street, identity.street);
  fillEmpty(fields.city, identity.city);
  fillEmpty(fields.postalCode, identity.postalCode);
  const c = identity.country.toLowerCase();
  fillEmpty(fields.country, identity.country, (v, t) => v.toLowerCase() === c || t.toLowerCase() === c);
  return filled;
}
