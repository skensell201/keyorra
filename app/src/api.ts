import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

/** Keep in sync with ClipboardGuard::DEFAULT_CLEAR_SECS (lockbox-session). */
export const CLIPBOARD_CLEAR_SECS = 90;

export type Status = "new" | "locked" | "unlocked";

export type ErrorKind = "wrongPassword" | "locked" | "throttled" | "notFound" | "invalid" | "other";
export interface CmdError {
  kind: ErrorKind;
  message: string;
  retryAfter?: number;
}

export function isCmdError(e: unknown): e is CmdError {
  return typeof e === "object" && e !== null && "kind" in e && "message" in e;
}

export function errorMessage(e: unknown): string {
  return isCmdError(e) ? e.message : String(e);
}

export type ItemKind = "login" | "secure_note" | "credit_card" | "identity" | "password" | "api_credential";

/** Matches lockbox-core's `FieldValue` JSON. */
export type FieldValue =
  | { type: "text" | "concealed" | "email" | "url" | "totp" | "phone"; value: string }
  | { type: "date"; value: number }
  | { type: "month_year"; value: number };

export interface Field {
  id: string;
  label: string;
  value: FieldValue;
  purpose?: "username" | "password";
}

export interface Section {
  id: string;
  title: string;
  fields: Field[];
}

/** lockbox-core's `Item`, snake_case as stored. Send it back unchanged except edited fields. */
export interface Item {
  id: string;
  vault_id: string;
  kind: ItemKind;
  title: string;
  tags: string[];
  favorite: boolean;
  urls: string[];
  fields: Field[];
  sections: Section[];
  notes: string;
  password_history: { value: string; changed_at: number }[];
  attachments: { id: string; name: string; size: number }[];
  created_at: number;
  updated_at: number;
}

export interface Vault {
  id: string;
  name: string;
  itemCount: number;
}

export interface ItemSummary {
  id: string;
  vaultId: string;
  kind: ItemKind | null;
  title: string;
  subtitle: string;
  favorite: boolean;
  hasTotp: boolean;
  updatedAt: number;
  damaged: boolean;
}

export interface ItemFilter {
  vaultId?: string | null;
  query?: string;
  favorites?: boolean;
}

export interface TotpCode {
  code: string;
  secondsLeft: number;
  period: number;
}

export interface GeneratorRequest {
  kind: "password" | "passphrase";
  length: number;
  lowercase: boolean;
  uppercase: boolean;
  digits: boolean;
  symbols: boolean;
  avoidAmbiguous: boolean;
  words: number;
  separator: string;
  capitalize: boolean;
  includeNumber: boolean;
}

export interface ImportPreview {
  vaults: { name: string; items: number }[];
  skipped: { title: string; reason: string }[];
  totalItems: number;
}

export interface ImportResult {
  vaults: number;
  items: number;
  attachments: number;
}

export const api = {
  status: () => invoke<Status>("status"),
  create: (password: string) => invoke<void>("create_vault_file", { password }),
  unlock: (password: string) => invoke<void>("unlock", { password }),
  lock: () => invoke<void>("lock"),
  vaults: () => invoke<Vault[]>("vaults"),
  createVault: (name: string) => invoke<Vault>("create_vault", { name }),
  items: (filter: ItemFilter) => invoke<ItemSummary[]>("items", { filter }),
  item: (id: string) => invoke<Item>("item", { id }),
  newItem: (vaultId: string, kind: ItemKind) => invoke<Item>("new_item", { vaultId, kind }),
  saveItem: (item: Item) => invoke<Item>("save_item", { item }),
  deleteItem: (id: string) => invoke<void>("delete_item", { id }),
  totp: (id: string) => invoke<TotpCode | null>("totp", { id }),
  copyField: (id: string, field: string) => invoke<void>("copy_field", { id, field }),
  generate: (request: GeneratorRequest) => invoke<string>("generate", { request }),
  importPreview: (path: string) => invoke<ImportPreview>("import_preview", { path }),
  importApply: () => invoke<ImportResult>("import_apply"),
  onLocked: (callback: () => void): Promise<UnlistenFn> => listen("locked", () => callback()),
};
