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

function usable(el: HTMLInputElement): boolean {
  if (el.disabled || el.readOnly || el.type === "hidden") return false;
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
