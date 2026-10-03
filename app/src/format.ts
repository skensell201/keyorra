import type { FieldValue, ItemKind } from "./api";

export const KIND_LABEL: Record<ItemKind, string> = {
  login: "Login",
  secure_note: "Secure note",
  credit_card: "Credit card",
  identity: "Identity",
  password: "Password",
  api_credential: "API credential",
};

export const NEW_KINDS: ItemKind[] = ["login", "secure_note", "password", "credit_card", "identity", "api_credential"];

export function fieldText(value: FieldValue): string {
  switch (value.type) {
    case "date":
      return new Date(value.value * 1000).toISOString().slice(0, 10);
    case "month_year":
      return `${String(value.value % 100).padStart(2, "0")}/${Math.floor(value.value / 100)}`;
    default:
      return value.value;
  }
}

export function formatCode(code: string): string {
  if (code.length === 6) return `${code.slice(0, 3)} ${code.slice(3)}`;
  if (code.length === 8) return `${code.slice(0, 4)} ${code.slice(4)}`;
  return code;
}
