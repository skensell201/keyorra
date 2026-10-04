import type { LoginFields } from "./detect";
import type { Credentials } from "./client";

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
