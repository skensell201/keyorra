import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export type QuickCopy = "username" | "password" | "totp";

export type Status = "new" | "locked" | "unlocked";

export type ErrorKind =
  | "wrongPassword"
  | "locked"
  | "throttled"
  | "notFound"
  | "invalid"
  | "notADatabase"
  | "passwordRequired"
  | "cancelled"
  | "other";
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

/** Matches keyorra-core's `FieldValue` JSON. */
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

/** keyorra-core's `Item`, snake_case as stored. Send it back unchanged except edited fields. */
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

export interface Settings {
  autoLockMinutes: number;
  clipboardSeconds: number;
}

export interface WatchtowerFinding {
  item: ItemSummary;
  detail: string;
}

export interface WatchtowerReport {
  breached: WatchtowerFinding[];
  reused: WatchtowerFinding[];
  weak: WatchtowerFinding[];
  missingTwoFactor: WatchtowerFinding[];
  breachesChecked: boolean;
  uncheckedPasswords: number;
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

export interface PairingRequest {
  clientId: string;
  name: string;
  code: string;
}

export interface PairedBrowser {
  clientId: string;
  name: string;
  createdAt: number;
}

export interface TouchIdState {
  /** This Mac has Touch ID with enrolled fingers. */
  available: boolean;
  enabled: boolean;
  /** 14 days since the master password was entered: Touch ID waits for it. */
  passwordDue: boolean;
}

export interface SyncDevice {
  id: string;
  name: string;
  approved: boolean;
  main: boolean;
  thisDevice: boolean;
  removed: boolean;
}

export interface SyncStatus {
  mainDevice: boolean;
  waitingForApproval: boolean;
  /** This Mac's key code, compared on the main Mac before it approves this one. */
  keyCode: string;
  devices: SyncDevice[];
  alarms: number;
  /** Other devices' changes are confirmed by the main Mac's newest decisions. */
  rootConfirmed: boolean;
}

export type AlarmAction = "accept" | "restore" | "remove" | "leave";

export interface SyncAlarm {
  id: string;
  kind: string;
  title: string;
  explanation: string;
  actions: AlarmAction[];
}

export interface LogLine {
  at: number;
  text: string;
}

export interface SyncScreen {
  enabled: boolean;
  running: boolean;
  error: string | null;
  location: string | null;
  lastRoundAt: number | null;
  lastRoundOk: boolean | null;
  status: SyncStatus | null;
  alarms: SyncAlarm[];
  notices: string[];
  log: LogLine[];
}

/** The setup code stays in Rust: `copySetupCode` puts it on the clipboard. */
export interface EmergencyKit {
  accountId: string;
  secretKey: string;
  /** The account's folder, when known. */
  location: string | null;
}

export interface JoinOutcome {
  mode: "new" | "rejoined" | "carriedOver";
  keyCode: string;
  copied: number;
  trashedLeft: number;
  damaged: number;
}

export interface VerifyReport {
  items: number;
  damaged: number;
  attachments: number;
  damagedAttachments: number;
  differing: string[];
  missing: number;
}

export interface FolderFile {
  path: string;
  size: number;
  /** A name Keyorra reads; false: an unknown file, ignored. */
  counted: boolean;
}

export interface BackupFile {
  name: string;
  size: number;
  modified: number;
  kind: "migration" | "preSync";
}

export interface SyncPlace {
  path: string;
  kind: "icloud" | "cloudStorage" | "network" | "local";
  warning: string | null;
}

export const api = {
  status: () => invoke<Status>("status"),
  create: (password: string) => invoke<void>("create_vault_file", { password }),
  unlock: (password: string) => invoke<void>("unlock", { password }),
  lock: () => invoke<void>("lock"),
  vaults: () => invoke<Vault[]>("vaults"),
  createVault: (name: string) => invoke<Vault>("create_vault", { name }),
  renameVault: (id: string, name: string) => invoke<Vault>("rename_vault", { id, name }),
  deleteVault: (id: string) => invoke<void>("delete_vault", { id }),
  /** Moves an unreadable database aside; returns where it went. */
  startOver: () => invoke<string>("start_over"),
  watchtower: () => invoke<WatchtowerReport>("watchtower"),
  /** Items Watchtower flags; cheap (cached until the next change). */
  watchtowerCount: () => invoke<number>("watchtower_count"),
  checkBreaches: () => invoke<WatchtowerReport>("check_breaches"),
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
  deletedItems: () => invoke<ItemSummary[]>("deleted_items"),
  restoreItem: (id: string) => invoke<void>("restore_item", { id }),
  settings: () => invoke<Settings>("settings"),
  updateSettings: (settings: Settings) => invoke<Settings>("update_settings", { settings }),
  changePassword: (current: string, newPassword: string) =>
    invoke<void>("change_password", { current, newPassword }),
  connectBrowsers: () => invoke<string[]>("connect_browsers"),
  approvePairing: (clientId: string) => invoke<void>("approve_pairing", { clientId }),
  denyPairing: (clientId: string) => invoke<void>("deny_pairing", { clientId }),
  pairedBrowsers: () => invoke<PairedBrowser[]>("paired_browsers"),
  removePairedBrowser: (clientId: string) => invoke<void>("remove_paired_browser", { clientId }),
  onPairRequest: (callback: (request: PairingRequest) => void): Promise<UnlistenFn> =>
    listen<PairingRequest>("pair-request", (e) => callback(e.payload)),
  onLocked: (callback: () => void): Promise<UnlistenFn> => listen("locked", () => callback()),
  onUnlocked: (callback: () => void): Promise<UnlistenFn> => listen("unlocked", () => callback()),
  /** The quick-search window was just shown (⌘⇧Space or the menu bar). */
  onQuickOpen: (callback: () => void): Promise<UnlistenFn> => listen("quick-open", () => callback()),
  quickCopy: (id: string, what: QuickCopy) => invoke<void>("quick_copy", { id, what }),
  quickHide: () => invoke<void>("quick_hide"),
  touchIdState: () => invoke<TouchIdState>("touch_id_state"),
  enableTouchId: () => invoke<void>("enable_touch_id"),
  disableTouchId: () => invoke<void>("disable_touch_id"),
  /** Shows the system Touch ID prompt; rejects with kind "cancelled" when dismissed. */
  unlockWithTouchId: () => invoke<void>("unlock_with_touch_id"),
  onItemsChanged: (callback: () => void): Promise<UnlistenFn> => listen("items-changed", () => callback()),
  syncScreen: () => invoke<SyncScreen>("sync_screen"),
  syncNow: () => invoke<SyncScreen>("sync_now"),
  enableSync: (password: string) => invoke<EmergencyKit>("enable_sync", { password }),
  joinSync: (password: string, code: string) => invoke<JoinOutcome>("join_sync", { password, code }),
  disableSync: () => invoke<void>("disable_sync"),
  approveDevice: (id: string, code: string) => invoke<void>("approve_device", { id, code }),
  syncAlarmAction: (id: string, action: AlarmAction) => invoke<void>("sync_alarm_action", { id, action }),
  removeSyncDevice: (id: string) => invoke<void>("remove_sync_device", { id }),
  verifySync: () => invoke<VerifyReport>("verify_sync"),
  syncFolderFiles: () => invoke<FolderFile[]>("sync_folder_files"),
  /** Without a password: only within a few minutes of entering it (else "passwordRequired"). */
  emergencyKit: (password: string | null) => invoke<EmergencyKit>("emergency_kit", { password }),
  startNewSyncAccount: (password: string) => invoke<EmergencyKit>("start_new_sync_account", { password }),
  backups: () => invoke<BackupFile[]>("backups"),
  deleteBackup: (name: string) => invoke<void>("delete_backup", { name }),
  syncPlace: () => invoke<SyncPlace | null>("sync_place"),
  /** `null`: iCloud Drive. Only while sync is off. */
  setSyncPlace: (path: string | null) => invoke<SyncPlace>("set_sync_place", { path }),
  /**
   * The setup code on the clipboard, concealed from clipboard managers and cleared after 90 s
   * at most. Same rule as `emergencyKit` (else "passwordRequired").
   */
  copySetupCode: (password: string | null = null) => invoke<void>("copy_setup_code", { password }),
  onSynced: (callback: () => void): Promise<UnlistenFn> => listen("synced", () => callback()),
  /** The main Mac: how many devices wait for approval (sent when it changes). */
  onSyncApproval: (callback: (waiting: number) => void): Promise<UnlistenFn> =>
    listen<number>("sync-approval", (e) => callback(e.payload)),
};
