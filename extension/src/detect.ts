// Finds the username, password and one-time-code fields on a page.

export interface LoginFields {
  username: HTMLInputElement | null;
  password: HTMLInputElement | null;
  totp: HTMLInputElement | null;
}

const USER_HINT = /user|login|email|e-mail|account|phone|ident|логин|почт/i;
const TOTP_HINT = /otp|totp|2fa|mfa|one.?time|verification|auth.?code|security.?code|код/i;
const NOT_USERNAME = /search|query|^q$/i;
const TEXTISH = new Set(["text", "email", "tel", "number", ""]);

export type Field = HTMLInputElement | HTMLSelectElement;

export function usable(el: Field): boolean {
  if (el.disabled || ("readOnly" in el && el.readOnly) || ("type" in el && el.type === "hidden")) return false;
  if (el.closest('[aria-hidden="true"]')) return false;
  if (typeof el.checkVisibility === "function") {
    if (!el.checkVisibility({ opacityProperty: true, visibilityProperty: true, contentVisibilityAuto: true })) return false;
  } else {
    // Fallback (jsdom): walk the style chain.
    for (let n: HTMLElement | null = el; n; n = n.parentElement) {
      const s = getComputedStyle(n);
      if (n.hidden || s.display === "none" || s.visibility === "hidden" || s.opacity === "0") return false;
    }
  }
  // Zero-size fields are hidden too, but only where there is layout at all.
  if (document.documentElement.getBoundingClientRect().width > 0) {
    const r = el.getBoundingClientRect();
    if (r.width === 0 || r.height === 0) return false;
  }
  return true;
}

function hints(el: HTMLInputElement): string {
  const label = el.labels?.[0]?.textContent ?? "";
  return [el.name, el.id, el.placeholder, el.getAttribute("aria-label") ?? "", label].join(" ");
}

function isTotp(el: HTMLInputElement): boolean {
  if (el.autocomplete === "one-time-code") return true;
  if (!TEXTISH.has(el.type)) return false;
  const short = el.maxLength >= 4 && el.maxLength <= 8;
  return TOTP_HINT.test(hints(el)) && (short || el.inputMode === "numeric" || el.type === "tel" || el.type === "number");
}

export function findLoginFields(root: Document | HTMLElement): LoginFields {
  const inputs = Array.from(root.querySelectorAll("input")).filter(usable);
  const password =
    inputs.find((i) => i.type === "password" && i.autocomplete === "current-password") ??
    inputs.find((i) => i.type === "password" && i.autocomplete !== "new-password") ??
    null;
  const totp = inputs.find((i) => i !== password && isTotp(i)) ?? null;
  const candidates = inputs.filter(
    (i) => i !== totp && TEXTISH.has(i.type) && i.type !== "number" && !NOT_USERNAME.test(i.name) && !NOT_USERNAME.test(i.id),
  );
  const before = (i: HTMLInputElement) => !!(i.compareDocumentPosition(password!) & Node.DOCUMENT_POSITION_FOLLOWING);
  // Prefer fields in the password's own form; fall back to the whole document.
  const own = password?.form ? candidates.filter((i) => i.form === password.form && before(i)) : [];
  const scope = password ? (own.length ? own : candidates.filter(before)) : candidates;
  const username =
    scope.find((i) => i.autocomplete === "username" || i.autocomplete === "email") ??
    (password ? scope[scope.length - 1] : scope.find((i) => i.type === "email" || USER_HINT.test(hints(i)))) ??
    null;
  return { username: username ?? null, password, totp };
}

// ---- new-password, card and address fields ----

function allFields(root: Document | HTMLElement): Field[] {
  return Array.from(root.querySelectorAll<Field>("input, select")).filter(usable);
}

const MIN_SIDE = 8;
const MIN_OPACITY = 0.1;

/** For fields that receive card and address data: big enough to be seen, on the page and not faded out.
 * Layout checks apply only where there is layout at all (not in jsdom). */
export function plausible(el: Field): boolean {
  for (let n: Element | null = el; n; n = n.parentElement) {
    if (parseFloat(getComputedStyle(n).opacity) < MIN_OPACITY) return false;
  }
  if (document.documentElement.getBoundingClientRect().width > 0) {
    const r = el.getBoundingClientRect();
    if (r.width < MIN_SIDE || r.height < MIN_SIDE) return false;
    // Parked off the top or left of the document, where no one can scroll to it.
    if (r.right + window.scrollX <= 0 || r.bottom + window.scrollY <= 0) return false;
  }
  return true;
}

function visibleFields(root: Document | HTMLElement): Field[] {
  return allFields(root).filter(plausible);
}

function isInput(el: Field): el is HTMLInputElement {
  return el.tagName === "INPUT";
}

/** Individual hint strings (name, id, placeholder, aria-label, label), tested one by one. */
function hintParts(el: Field): string[] {
  const label = el.labels?.[0]?.textContent ?? "";
  const ph = isInput(el) ? el.placeholder : "";
  return [el.name, el.id, ph, el.getAttribute("aria-label") ?? "", label].map((p) => p.trim()).filter(Boolean);
}

function hintMatch(el: Field, re: RegExp): boolean {
  return hintParts(el).some((p) => re.test(p));
}

/** The autocomplete token that names the field (the last one, e.g. "section-a cc-number"). */
function ac(el: Field): string {
  const tokens = (el.getAttribute("autocomplete") ?? "").toLowerCase().trim().split(/\s+/);
  return tokens[tokens.length - 1] ?? "";
}

const OLD_PASSWORD = /current|old|existing/i;

export function findNewPasswordFields(root: Document | HTMLElement): HTMLInputElement[] {
  const pws = allFields(root).filter((i): i is HTMLInputElement => isInput(i) && i.type === "password");
  const groups = new Map<HTMLFormElement | null, HTMLInputElement[]>();
  for (const p of pws) groups.set(p.form, [...(groups.get(p.form) ?? []), p]);
  const out: HTMLInputElement[] = [];
  for (const list of groups.values()) {
    const marked = list.filter((p) => ac(p) === "new-password");
    if (marked.length) out.push(...marked);
    else if (list.length === 2) {
      // Sign-up with a confirmation, unless the first one asks for the current password.
      const [first, second] = list;
      const old = [first.name, first.id, first.getAttribute("autocomplete") ?? "", first.placeholder].some((h) => OLD_PASSWORD.test(h));
      out.push(...(old ? [second] : list));
    } else if (list.length === 3) out.push(...list.slice(1)); // current, new, confirm
  }
  return out;
}

export interface CardFields {
  number: Field | null;
  name: Field | null;
  exp: Field | null;
  expMonth: Field | null;
  expYear: Field | null;
  cvc: Field | null;
}

const CARD_NUMBER = /card.?num|cc.?num|cardnumber/i;
const CARD_NAME = /name.?on.?card|cardholder|cc.?name/i;
const CARD_EXP = /exp(iry|iration)?(.?date)?$|mm.{0,3}yy|cc.?exp$/i;
const CARD_MONTH = /exp.*month|cc.?month|\bmm\b/i;
const CARD_YEAR = /exp.*year|cc.?year|\byy(yy)?\b/i;
const CARD_CVC = /cvc|cvv|csc|security.?code/i;

export function findCardFields(root: Document | HTMLElement): CardFields {
  const fields = visibleFields(root);
  const taken = new Set<Field>();
  const pick = (token: string, re: RegExp, accept: (el: Field) => boolean): Field | null => {
    const free = fields.filter((f) => !taken.has(f) && accept(f));
    const found = free.find((f) => ac(f) === token) ?? free.find((f) => hintMatch(f, re)) ?? null;
    if (found) taken.add(found);
    return found;
  };
  const text = (el: Field) => isInput(el) && TEXTISH.has(el.type);
  // A CVC is often masked; no other card field is ever a password input.
  const secret = (el: Field) => isInput(el) && (TEXTISH.has(el.type) || el.type === "password");
  const any = (el: Field) => isInput(el) ? TEXTISH.has(el.type) : true;
  const none: CardFields = { number: null, name: null, exp: null, expMonth: null, expYear: null, cvc: null };
  const number = pick("cc-number", CARD_NUMBER, text);
  if (!number) return none;
  const exp = pick("cc-exp", CARD_EXP, text);
  return {
    number,
    name: pick("cc-name", CARD_NAME, text),
    cvc: pick("cc-csc", CARD_CVC, secret),
    exp,
    expMonth: pick("cc-exp-month", CARD_MONTH, any),
    expYear: pick("cc-exp-year", CARD_YEAR, any),
  };
}

export interface AddressFields {
  givenName: Field | null;
  familyName: Field | null;
  name: Field | null;
  email: Field | null;
  phone: Field | null;
  street: Field | null;
  city: Field | null;
  postalCode: Field | null;
  country: Field | null;
}

const ADDR_GIVEN = /first.?name|given|fname|^имя$/i;
const ADDR_FAMILY = /last.?name|family|surname|lname|фамилия/i;
const ADDR_NAME = /^(full.?)?name$/i;
const ADDR_EMAIL = /e-?mail|почт/i;
const ADDR_PHONE = /phone|^tel|mobile|телефон/i;
const ADDR_STREET = /street|address.?(line)?.?1?$|address1/i;
const ADDR_CITY = /city|town|locality|город/i;
const ADDR_POSTAL = /zip|postal|post.?code|индекс/i;
const ADDR_COUNTRY = /country|страна/i;

const CARD_HINT = new RegExp(`${CARD_NUMBER.source}|${CARD_NAME.source}|${CARD_CVC.source}`, "i");

export function findAddressFields(root: Document | HTMLElement): AddressFields {
  const fields = visibleFields(root).filter(
    (f) => !(isInput(f) && f.type === "password") && !ac(f).startsWith("cc-") && !hintMatch(f, CARD_HINT),
  );
  const taken = new Set<Field>();
  const pick = (tokens: string[], re: RegExp, accept: (el: Field) => boolean = (el) => isInput(el) && TEXTISH.has(el.type)): Field | null => {
    const free = fields.filter((f) => !taken.has(f) && accept(f));
    const found = free.find((f) => tokens.includes(ac(f))) ?? free.find((f) => hintMatch(f, re)) ?? null;
    if (found) taken.add(found);
    return found;
  };
  const f: AddressFields = {
    givenName: pick(["given-name"], ADDR_GIVEN),
    familyName: pick(["family-name"], ADDR_FAMILY),
    name: pick(["name"], ADDR_NAME),
    email: pick(["email"], ADDR_EMAIL, (el) => isInput(el) && (TEXTISH.has(el.type))),
    phone: pick(["tel"], ADDR_PHONE),
    street: pick(["street-address", "address-line1"], ADDR_STREET),
    city: pick(["address-level2"], ADDR_CITY),
    postalCode: pick(["postal-code"], ADDR_POSTAL),
    country: pick(["country", "country-name"], ADDR_COUNTRY, () => true),
  };
  const real = [f.givenName, f.familyName, f.name, f.street, f.city, f.postalCode, f.country].filter(Boolean).length;
  if (real < 2) {
    return { givenName: null, familyName: null, name: null, email: null, phone: null, street: null, city: null, postalCode: null, country: null };
  }
  return f;
}
