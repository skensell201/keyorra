# Keyorra Sync A3-2 Implementation Plan (the Sync screen and setup flows in the app)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The user turns sync on, joins, approves and manages devices in the app. Settings → Sync opens the Sync screen: with sync off, where accounts go (iCloud Drive or another folder, with a note on what to keep in mind), turning sync on with the master password (this Mac becomes the main Mac) and the Emergency Kit to print, or joining a synced account; with sync on, status, devices waiting for approval (approved by typing the code the new Mac shows), alarms with their explanation and actions, notices, devices (the main Mac removes them), the Emergency Kit again, Verify everything, What the folder sees, the vault's backup copies, the log, turning sync off and starting a new account. The first-run screen offers "Join your synced account". A banner above the item details says when devices ask to join, when sync needs attention or stopped, and when other devices' changes are not yet confirmed by the main Mac; the item list refreshes after every round.

**Builds on:** A3-1 (`docs/superpowers/plans/2026-10-06-keyorra-sync-a3-1.md`).

**Verified:** every task was applied in order in a scratch worktree on top of A3-1; after each task `pnpm exec tsc --noEmit` is clean and `pnpm exec vitest run` passes (126 tests at the end, 109 before); the Rust suite is unchanged.

**Architecture:** `api.ts` gains the sync types and calls. New components: `EmergencyKit` (print first; copy the setup code concealed), `JoinSync` and `JoinResult`, `ApproveDialog`, `SyncDialog` (with `SyncOff`, `SyncOn`, `StartOverDialog`), `SyncBanner`. `Main` shows the banner and the dialog; `SettingsDialog` gets a Sync section; `Setup` offers joining. Styles use the existing tokens; a print stylesheet prints only the kit.

## Spec changes (patch for the coordinator to apply with this plan)

Spec §9.1 gains: "Approving a device: the main Mac shows the joining device's name and asks for the code the new Mac shows; the Approve button works only once 12 letters and digits are typed (case and dashes ignored) and the session compares them." and "The first-run screen offers joining; joining an existing vault from Settings → Sync merges by record id (same account) or carries the items over (another account), and reports what stayed in the old file." §12: "**A3-1** Sync screen backend … **A3-2** Sync screen and flows in the app (Vitest)".

## Decisions that need the user (wording and defaults)

- **Words.** "Main Mac" for the root device; "Turn on sync" / "Turn off sync"; "Join a synced account"; "Waiting for your main Mac"; "Start a new account"; "Emergency Kit"; "What the folder sees"; "Verify everything". Alarm titles and explanations are in `crates/keyorra-session/src/sync/screen.rs` (A3-1), e.g. "Changes of Laptop went missing from the sync folder", "Two different histories of Laptop", "Something occupies this Mac's place in the sync folder".
- **Approval by typing the code** (not by looking and clicking): slower, but a user cannot approve a replaced request by habit.
- **Emergency Kit**: Print is the primary button; "Save as PDF" is not offered (the print dialog still allows it; the kit warns against saving it in a synced folder). Shown again without the password only within 5 minutes of entering it.
- **The setup code is copied, not shown as a QR code** (no camera on most Macs); concealed from clipboard managers, cleared after 90 s.
- **Unconfirmed changes are a banner for the account**, not a badge per item (the engine does not track it per record).
- **No device rename** (names come with the joining request and are signed).
- **Joining another account's vault always carries the items over** (no "Replace"); the old file stays next to the vault and is listed under the backup copies, with delete.
- **The log lives until the vault locks** (not on disk).
- **The banner's words**: "1 device asked to join your account" (Review), "Sync needs your attention", "Sync stopped: …", "Changes from other devices aren't confirmed by your main Mac yet".
- **The sync folder can be changed only while sync is off.**

## Conventions for every task

- Test first: write the test, run it, see it fail for the expected reason, implement, see it pass, commit.
- English only. Every commit message ends with these two lines (omitted below; always add them):

```
Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_016B8vpfBkT1rhCY8NF4kPbd
```

- Rust from the repo root: `cargo fmt --all`; `cargo clippy --workspace --all-targets -- -D warnings`; the touched crates' tests. Frontend from `app/`: `pnpm exec tsc --noEmit`; `pnpm exec vitest run`.
- Shell: an `rtk` proxy may filter output; `rtk proxy <cmd>` runs it raw (use it for vitest: the proxy otherwise writes `app/.vitest/`). Plain `grep` with a glob through the proxy can miss matches; use `grep -rn <dir>`.
- Patches below are `git diff` output against the state after the previous task; apply them with `git apply` (or by hand), in task order. New files are given in full.
- Never run `--ignored` tests; never touch the real keychain, Secure Enclave or iCloud from tests.
- Work on `feat/sync-design`; do not push.

## File map

```
app/src/api.ts                               sync types and calls
app/src/components/EmergencyKit.tsx (+test)  NEW
app/src/components/JoinSync.tsx (+test)      NEW JoinSync, JoinResult
app/src/components/ApproveDialog.tsx         NEW (tested through SyncDialog)
app/src/components/SyncDialog.tsx (+test)    NEW
app/src/test/sync.ts                         NEW test fixture
app/src/components/SyncBanner.tsx (+test)    NEW
app/src/components/{Main,SettingsDialog,Setup}.tsx (+ Main, App, Setup tests)
app/src/styles.css                           sync styles, print stylesheet
```

---

### Task 1: Sync in the API

**Files:** Modify `app/src/api.ts`.

- [ ] **Step 1: Implement.**

Types and calls only (used by the next tasks):

```diff
diff --git a/app/src/api.ts b/app/src/api.ts
index 035eac0..f32f94c 100644
--- a/app/src/api.ts
+++ b/app/src/api.ts
@@ -163,6 +163,97 @@ export interface TouchIdState {
   passwordDue: boolean;
 }
 
+export interface SyncDevice {
+  id: string;
+  name: string;
+  approved: boolean;
+  main: boolean;
+  thisDevice: boolean;
+  removed: boolean;
+}
+
+export interface SyncStatus {
+  mainDevice: boolean;
+  waitingForApproval: boolean;
+  /** This Mac's key code, compared on the main Mac before it approves this one. */
+  keyCode: string;
+  devices: SyncDevice[];
+  alarms: number;
+  /** Other devices' changes are confirmed by the main Mac's newest decisions. */
+  rootConfirmed: boolean;
+}
+
+export type AlarmAction = "accept" | "restore" | "remove" | "leave";
+
+export interface SyncAlarm {
+  id: string;
+  kind: string;
+  title: string;
+  explanation: string;
+  actions: AlarmAction[];
+}
+
+export interface LogLine {
+  at: number;
+  text: string;
+}
+
+export interface SyncScreen {
+  enabled: boolean;
+  running: boolean;
+  error: string | null;
+  location: string | null;
+  lastRoundAt: number | null;
+  lastRoundOk: boolean | null;
+  status: SyncStatus | null;
+  alarms: SyncAlarm[];
+  notices: string[];
+  log: LogLine[];
+}
+
+export interface EmergencyKit {
+  accountId: string;
+  secretKey: string;
+  setupCode: string;
+}
+
+export interface JoinOutcome {
+  mode: "new" | "rejoined" | "carriedOver";
+  keyCode: string;
+  copied: number;
+  trashedLeft: number;
+  damaged: number;
+}
+
+export interface VerifyReport {
+  items: number;
+  damaged: number;
+  attachments: number;
+  damagedAttachments: number;
+  differing: string[];
+  missing: number;
+}
+
+export interface FolderFile {
+  path: string;
+  size: number;
+  /** A name Keyorra reads; false: an unknown file, ignored. */
+  counted: boolean;
+}
+
+export interface BackupFile {
+  name: string;
+  size: number;
+  modified: number;
+  kind: "migration" | "preSync";
+}
+
+export interface SyncPlace {
+  path: string;
+  kind: "icloud" | "cloudStorage" | "network" | "local";
+  warning: string | null;
+}
+
 export const api = {
   status: () => invoke<Status>("status"),
   create: (password: string) => invoke<void>("create_vault_file", { password }),
@@ -213,4 +304,28 @@ export const api = {
   /** Shows the system Touch ID prompt; rejects with kind "cancelled" when dismissed. */
   unlockWithTouchId: () => invoke<void>("unlock_with_touch_id"),
   onItemsChanged: (callback: () => void): Promise<UnlistenFn> => listen("items-changed", () => callback()),
+  syncScreen: () => invoke<SyncScreen>("sync_screen"),
+  syncNow: () => invoke<SyncScreen>("sync_now"),
+  enableSync: (password: string) => invoke<EmergencyKit>("enable_sync", { password }),
+  joinSync: (password: string, code: string) => invoke<JoinOutcome>("join_sync", { password, code }),
+  disableSync: () => invoke<void>("disable_sync"),
+  approveDevice: (id: string, code: string) => invoke<void>("approve_device", { id, code }),
+  syncAlarmAction: (id: string, action: AlarmAction) => invoke<void>("sync_alarm_action", { id, action }),
+  removeSyncDevice: (id: string) => invoke<void>("remove_sync_device", { id }),
+  verifySync: () => invoke<VerifyReport>("verify_sync"),
+  syncFolderFiles: () => invoke<FolderFile[]>("sync_folder_files"),
+  /** Without a password: only within a few minutes of entering it (else "passwordRequired"). */
+  emergencyKit: (password: string | null) => invoke<EmergencyKit>("emergency_kit", { password }),
+  startNewSyncAccount: (password: string) => invoke<EmergencyKit>("start_new_sync_account", { password }),
+  backups: () => invoke<BackupFile[]>("backups"),
+  deleteBackup: (name: string) => invoke<void>("delete_backup", { name }),
+  syncPlace: () => invoke<SyncPlace | null>("sync_place"),
+  /** `null`: iCloud Drive. Only while sync is off. */
+  setSyncPlace: (path: string | null) => invoke<SyncPlace>("set_sync_place", { path }),
+  /** Concealed from clipboard managers, cleared after 90 s at most. */
+  copySecret: (text: string) => invoke<void>("copy_secret", { text }),
+  onSynced: (callback: () => void): Promise<UnlistenFn> => listen("synced", () => callback()),
+  /** The main Mac: how many devices wait for approval (sent when it changes). */
+  onSyncApproval: (callback: (waiting: number) => void): Promise<UnlistenFn> =>
+    listen<number>("sync-approval", (e) => callback(e.payload)),
 };
```

- [ ] **Step 2: Check and commit.**

`pnpm exec tsc --noEmit`. Commit: `App A3-2: sync calls in the API`.

---

### Task 2: Emergency Kit, joining, approving

**Files:** Create `app/src/components/EmergencyKit.tsx`, `EmergencyKit.test.tsx`, `JoinSync.tsx`, `JoinSync.test.tsx`, `ApproveDialog.tsx`.

- [ ] **Step 1: Failing tests.**

Create `app/src/components/EmergencyKit.test.tsx`:

```tsx
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, test, vi } from "vitest";
import { api } from "../api";
import { EmergencyKit, groupHex } from "./EmergencyKit";

vi.mock("../api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api")>();
  return { ...actual, api: { ...actual.api, copySecret: vi.fn() } };
});

test("the kit shows the account and Secret Key, copies the setup code concealed", async () => {
  const user = userEvent.setup();
  vi.mocked(api.copySecret).mockResolvedValue(undefined);
  render(
    <EmergencyKit
      kit={{ accountId: "0123456789abcdef0123456789abcdef", secretKey: "A3KX-ABCDE", setupCode: "KEYORRA-SETUP-1-XYZ" }}
      location="/sync/Keyorra/0123"
      onDone={vi.fn()}
    />,
  );
  expect(screen.getByText("0123 4567 89ab cdef 0123 4567 89ab cdef")).toBeInTheDocument();
  expect(screen.getByText(/Don't save the kit as a file in iCloud Drive/)).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Copy setup code" }));
  expect(api.copySecret).toHaveBeenCalledWith("KEYORRA-SETUP-1-XYZ");
  expect(await screen.findByText(/clears from the clipboard in 90 seconds/)).toBeInTheDocument();
  expect(groupHex("abcdef")).toBe("abcd ef");
});
```

Create `app/src/components/JoinSync.test.tsx`:

```tsx
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { api } from "../api";
import { JoinResult, JoinSync } from "./JoinSync";

vi.mock("../api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api")>();
  return { ...actual, api: { ...actual.api, joinSync: vi.fn() } };
});

beforeEach(() => {
  vi.mocked(api.joinSync).mockReset();
});

test("joins with the password and the setup code", async () => {
  const user = userEvent.setup();
  const outcome = { mode: "new" as const, keyCode: "0a1b-2c3d-4e5f", copied: 0, trashedLeft: 0, damaged: 0 };
  vi.mocked(api.joinSync).mockResolvedValue(outcome);
  const onJoined = vi.fn();
  render(<JoinSync onJoined={onJoined} />);
  await user.type(screen.getByLabelText("Master password"), "correct horse battery");
  await user.type(screen.getByLabelText("Setup code or Secret Key"), "  KEYORRA-SETUP-1-XYZ ");
  await user.click(screen.getByRole("button", { name: "Join" }));
  expect(api.joinSync).toHaveBeenCalledWith("correct horse battery", "KEYORRA-SETUP-1-XYZ");
  expect(onJoined).toHaveBeenCalledWith(outcome);
});

test("a wrong password or key says so", async () => {
  const user = userEvent.setup();
  vi.mocked(api.joinSync).mockRejectedValue({ kind: "wrongPassword", message: "x" });
  render(<JoinSync onJoined={vi.fn()} />);
  await user.type(screen.getByLabelText("Master password"), "nope nope nope");
  await user.type(screen.getByLabelText("Setup code or Secret Key"), "A3KX");
  await user.click(screen.getByRole("button", { name: "Join" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("The master password or the Secret Key is wrong");
});

test("after joining: the code to compare, and what was carried over", () => {
  render(
    <JoinResult
      outcome={{ mode: "carriedOver", keyCode: "0a1b-2c3d-4e5f", copied: 7, trashedLeft: 2, damaged: 1 }}
      onDone={vi.fn()}
    />,
  );
  expect(screen.getByTestId("key-code")).toHaveTextContent("0a1b-2c3d-4e5f");
  expect(screen.getByText(/7 item\(s\) from this Mac were copied/)).toHaveTextContent(
    "2 in Recently Deleted and 1 unreadable item(s) stayed in the old file",
  );
});
```

(A `beforeEach` must not return the mock: Vitest calls a returned function as cleanup.)

- [ ] **Step 2: Emergency Kit.**

Create `app/src/components/EmergencyKit.tsx`:

```tsx
import { useState } from "react";
import { api, errorMessage, type EmergencyKit as Kit } from "../api";

/** Formats an account id (32 hex digits) in groups of four for reading aloud or copying. */
export function groupHex(hex: string) {
  return hex.match(/.{1,4}/g)?.join(" ") ?? hex;
}

/**
 * The Emergency Kit (spec §7.6): printing is the main action. The page holds the Secret Key:
 * it must not end up next to the encrypted data.
 */
export function EmergencyKit({ kit, location, onDone }: { kit: Kit; location: string | null; onDone: () => void }) {
  const [note, setNote] = useState("");
  async function copySetupCode() {
    try {
      await api.copySecret(kit.setupCode);
      setNote("Setup code copied. It clears from the clipboard in 90 seconds.");
    } catch (e) {
      setNote(errorMessage(e));
    }
  }
  return (
    <section className="modal-section kit" aria-label="Emergency Kit">
      <h3>Emergency Kit</h3>
      <p className="muted">
        Print this page and keep it with your important papers. With it and your master password you can reach your
        data on a new Mac if you lose all your devices. Without it, nobody can — not even us.
      </p>
      <dl className="kit-sheet">
        <dt>Account</dt>
        <dd className="mono">{groupHex(kit.accountId)}</dd>
        <dt>Secret Key</dt>
        <dd className="mono" data-testid="secret-key">
          {kit.secretKey}
        </dd>
        {location && (
          <>
            <dt>Sync folder</dt>
            <dd className="mono">{location}</dd>
          </>
        )}
        <dt>Master password</dt>
        <dd className="kit-blank">&nbsp;</dd>
      </dl>
      <p className="muted">
        Don't save the kit as a file in iCloud Drive, Dropbox or your sync folder: next to the encrypted data it would
        undo what the Secret Key protects.
      </p>
      <div className="modal-actions">
        <span className="status" role="status" aria-label="Emergency Kit">
          {note}
        </span>
        <button className="secondary" onClick={copySetupCode}>
          Copy setup code
        </button>
        <button className="secondary" onClick={onDone}>
          Done
        </button>
        <button className="primary" onClick={() => window.print()}>
          Print
        </button>
      </div>
    </section>
  );
}
```

- [ ] **Step 3: Joining.**

Create `app/src/components/JoinSync.tsx`:

```tsx
import { useState, type FormEvent } from "react";
import { api, errorMessage, isCmdError, type JoinOutcome } from "../api";

/**
 * Joining a synced account with the master password and the setup code shown on a Mac that
 * is set up (or the Secret Key from the Emergency Kit). Then this Mac waits until the main
 * Mac approves it, comparing the code shown here.
 */
export function JoinSync({ onJoined, onCancel }: { onJoined: (outcome: JoinOutcome) => void; onCancel?: () => void }) {
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const valid = password.length > 0 && code.trim().length > 0 && !busy;

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!valid) return;
    setBusy(true);
    setError(null);
    try {
      onJoined(await api.joinSync(password, code.trim()));
    } catch (err) {
      setError(
        isCmdError(err) && err.kind === "wrongPassword"
          ? "The master password or the Secret Key is wrong"
          : errorMessage(err),
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="join-sync" onSubmit={submit} aria-label="Join a synced account">
      <p className="muted">
        On a Mac where Keyorra already syncs, open Settings → Sync → Emergency Kit and copy the setup code. Paste it
        here with your master password.
      </p>
      <label>
        Master password
        <input type="password" autoFocus value={password} onChange={(e) => setPassword(e.target.value)} />
      </label>
      <label>
        Setup code or Secret Key
        <input
          className="mono"
          spellCheck={false}
          autoCapitalize="characters"
          value={code}
          onChange={(e) => setCode(e.target.value)}
        />
      </label>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      <div className="modal-actions">
        {onCancel && (
          <button type="button" onClick={onCancel} disabled={busy}>
            Cancel
          </button>
        )}
        <button type="submit" className="primary" disabled={!valid}>
          {busy ? "Joining…" : "Join"}
        </button>
      </div>
    </form>
  );
}

/** What happened after joining, and the code to compare on the main Mac. */
export function JoinResult({ outcome, onDone }: { outcome: JoinOutcome; onDone: () => void }) {
  return (
    <section className="join-result" aria-label="Joined">
      <h3>Waiting for your main Mac</h3>
      <p className="muted">
        On your main Mac, Keyorra asks whether to approve this Mac. Approve it only if it shows this code:
      </p>
      <p className="pair-code mono" data-testid="key-code">
        {outcome.keyCode}
      </p>
      {outcome.mode === "rejoined" && (
        <p className="muted">This vault rejoined its account. Items edited on both sides keep both versions.</p>
      )}
      {outcome.mode === "carriedOver" && (
        <p className="muted">
          {outcome.copied} item(s) from this Mac were copied into the account.
          {outcome.trashedLeft + outcome.damaged > 0 &&
            ` ${outcome.trashedLeft} in Recently Deleted and ${outcome.damaged} unreadable item(s) stayed in the old file, kept next to the vault.`} Touch ID is off for the new vault; turn it on again in Settings.
        </p>
      )}
      <div className="modal-actions">
        <button className="primary" onClick={onDone}>
          Continue
        </button>
      </div>
    </section>
  );
}
```

- [ ] **Step 4: Approving.**

Create `app/src/components/ApproveDialog.tsx`:

```tsx
import { useState } from "react";
import { api, errorMessage, type SyncDevice } from "../api";

/** Letters and digits only, lower case: how codes are compared. */
export function normalizeCode(code: string) {
  return code.toLowerCase().replace(/[^0-9a-z]/g, "");
}

/**
 * The main Mac approves a device that asked to join. The user types the code the other Mac
 * shows; a device whose request was replaced on the way shows another code.
 */
export function ApproveDialog({ device, onDone }: { device: SyncDevice; onDone: () => void }) {
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const complete = normalizeCode(code).length === 12;

  async function approve() {
    setBusy(true);
    setError(null);
    try {
      await api.approveDevice(device.id, code);
      onDone();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="modal-backdrop">
      <div className="card modal confirm" role="dialog" aria-modal="true" aria-labelledby="approve-title">
        <h2 id="approve-title">Approve “{device.name}”?</h2>
        <p className="muted">
          Approve only a Mac you just set up yourself. Type the code it shows under “Waiting for your main Mac”.
        </p>
        <label>
          Code shown on {device.name}
          <input
            className="mono"
            autoFocus
            spellCheck={false}
            placeholder="xxxx-xxxx-xxxx"
            value={code}
            onChange={(e) => setCode(e.target.value)}
          />
        </label>
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        <div className="modal-actions">
          <button onClick={onDone} disabled={busy}>
            Not now
          </button>
          <button className="primary" onClick={approve} disabled={!complete || busy}>
            Approve
          </button>
        </div>
      </div>
    </div>
  );
}
```

- [ ] **Step 5: Run and commit.**

`pnpm exec tsc --noEmit`; `pnpm exec vitest run`. Commit: `App A3-2: Emergency Kit, joining, approving a device`.

---

### Task 3: The Sync screen

**Files:** Create `app/src/components/SyncDialog.tsx`, `SyncDialog.test.tsx`, `app/src/test/sync.ts`.

- [ ] **Step 1: Failing tests.**

Create `app/src/test/sync.ts`:

```tsx
import type { SyncScreen } from "../api";

/** A synced main Mac with one approved laptop, as the Sync screen gets it. */
export function syncScreen(overrides: Partial<SyncScreen> = {}): SyncScreen {
  return {
    enabled: true,
    running: true,
    error: null,
    location: "/Users/a/Library/Mobile Documents/com~apple~CloudDocs/Keyorra/0101",
    lastRoundAt: 1_790_000_000,
    lastRoundOk: true,
    status: {
      mainDevice: true,
      waitingForApproval: false,
      keyCode: "0a1b-2c3d-4e5f",
      devices: [
        { id: "d0", name: "Main Mac", approved: true, main: true, thisDevice: true, removed: false },
        { id: "d1", name: "Laptop", approved: true, main: false, thisDevice: false, removed: false },
      ],
      alarms: 0,
      rootConfirmed: true,
    },
    alarms: [],
    notices: [],
    log: [{ at: 1_790_000_000, text: "Received 2 change(s) from Laptop" }],
    ...overrides,
  };
}
```

Create `app/src/components/SyncDialog.test.tsx` (turning sync on shows the kit and prints; another folder with its warning; an alarm's actions; removing a device after confirming; reviewing a device with its code; the kit asks for the password; verify, folder files and the log; turning off and starting a new account; deleting a backup copy):

```tsx
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { open } from "@tauri-apps/plugin-dialog";
import { beforeEach, expect, test, vi } from "vitest";
import { api } from "../api";
import { syncScreen } from "../test/sync";
import { SyncDialog } from "./SyncDialog";

vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn() }));
vi.mock("../api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api")>();
  return {
    ...actual,
    api: {
      ...actual.api,
      syncScreen: vi.fn(),
      syncNow: vi.fn(),
      onSynced: vi.fn(),
      syncPlace: vi.fn(),
      setSyncPlace: vi.fn(),
      enableSync: vi.fn(),
      joinSync: vi.fn(),
      disableSync: vi.fn(),
      syncAlarmAction: vi.fn(),
      removeSyncDevice: vi.fn(),
      verifySync: vi.fn(),
      syncFolderFiles: vi.fn(),
      emergencyKit: vi.fn(),
      startNewSyncAccount: vi.fn(),
      backups: vi.fn(),
      deleteBackup: vi.fn(),
      approveDevice: vi.fn(),
      copySecret: vi.fn(),
    },
  };
});

const off = syncScreen({ enabled: false, running: false, status: null, log: [] });
const kit = { accountId: "0101".repeat(8), secretKey: "A3KX-ABCDE-FGHJK", setupCode: "KEYORRA-SETUP-1-XYZ" };

beforeEach(() => {
  vi.mocked(api.syncScreen).mockReset().mockResolvedValue(syncScreen());
  vi.mocked(api.onSynced).mockReset().mockResolvedValue(() => {});
  vi.mocked(api.syncPlace).mockReset().mockResolvedValue({
    path: "/Users/a/Library/Mobile Documents/com~apple~CloudDocs/Keyorra",
    kind: "icloud",
    warning: null,
  });
  vi.mocked(api.backups).mockReset().mockResolvedValue([]);
  for (const f of [
    api.syncNow, api.setSyncPlace, api.enableSync, api.joinSync, api.disableSync, api.syncAlarmAction,
    api.removeSyncDevice, api.verifySync, api.syncFolderFiles, api.emergencyKit, api.startNewSyncAccount,
    api.deleteBackup, api.approveDevice, api.copySecret,
  ]) {
    vi.mocked(f).mockReset();
  }
});

test("turning sync on shows the Emergency Kit to print", async () => {
  const user = userEvent.setup();
  vi.mocked(api.syncScreen).mockResolvedValue(off);
  vi.mocked(api.enableSync).mockResolvedValue(kit);
  render(<SyncDialog onClose={vi.fn()} />);
  expect(await screen.findByText(/CloudDocs\/Keyorra/)).toBeInTheDocument();
  await user.type(screen.getByLabelText("Master password"), "correct horse battery");
  await user.click(screen.getByRole("button", { name: "Turn on sync" }));
  expect(api.enableSync).toHaveBeenCalledWith("correct horse battery");
  const sheet = await screen.findByRole("region", { name: "Emergency Kit" });
  expect(within(sheet).getByTestId("secret-key")).toHaveTextContent("A3KX-ABCDE-FGHJK");
  const print = vi.spyOn(window, "print").mockImplementation(() => {});
  await user.click(within(sheet).getByRole("button", { name: "Print" }));
  expect(print).toHaveBeenCalled();
});

test("another folder can be chosen, with its warning", async () => {
  const user = userEvent.setup();
  vi.mocked(api.syncScreen).mockResolvedValue(off);
  vi.mocked(open).mockResolvedValue("/Users/a/Library/CloudStorage/Dropbox");
  vi.mocked(api.setSyncPlace).mockResolvedValue({
    path: "/Users/a/Library/CloudStorage/Dropbox/Keyorra",
    kind: "cloudStorage",
    warning: "Set this folder to stay downloaded",
  });
  render(<SyncDialog onClose={vi.fn()} />);
  await user.click(await screen.findByRole("button", { name: "Choose another folder…" }));
  expect(api.setSyncPlace).toHaveBeenCalledWith("/Users/a/Library/CloudStorage/Dropbox");
  expect(await screen.findByText("Set this folder to stay downloaded")).toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Use iCloud Drive" }));
  expect(api.setSyncPlace).toHaveBeenLastCalledWith(null);
});

test("an alarm offers its actions", async () => {
  const user = userEvent.setup();
  vi.mocked(api.syncScreen).mockResolvedValue(
    syncScreen({
      alarms: [
        {
          id: "a1",
          kind: "rollback",
          title: "Changes of Laptop went missing from the sync folder",
          explanation: "The folder holds fewer of that device's changes.",
          actions: ["restore", "accept"],
        },
      ],
    }),
  );
  vi.mocked(api.syncAlarmAction).mockResolvedValue(undefined);
  render(<SyncDialog onClose={vi.fn()} />);
  const alarms = await screen.findByRole("region", { name: "Alarms" });
  expect(within(alarms).getByText(/went missing/)).toBeInTheDocument();
  await user.click(within(alarms).getByRole("button", { name: "Restore from this Mac" }));
  expect(api.syncAlarmAction).toHaveBeenCalledWith("a1", "restore");
});

test("the main Mac removes a device after confirming", async () => {
  const user = userEvent.setup();
  vi.mocked(api.removeSyncDevice).mockResolvedValue(undefined);
  render(<SyncDialog onClose={vi.fn()} />);
  const devices = await screen.findByRole("region", { name: "Devices" });
  await user.click(within(devices).getByRole("button", { name: "Remove" }));
  await user.click(screen.getByRole("button", { name: "Remove device" }));
  expect(api.removeSyncDevice).toHaveBeenCalledWith("d1");
});

test("a device waiting for approval is reviewed with its code", async () => {
  const user = userEvent.setup();
  const s = syncScreen();
  s.status!.devices.push({ id: "d2", name: "New Mac", approved: false, main: false, thisDevice: false, removed: false });
  vi.mocked(api.syncScreen).mockResolvedValue(s);
  vi.mocked(api.approveDevice).mockResolvedValue(undefined);
  render(<SyncDialog onClose={vi.fn()} />);
  const approvals = await screen.findByRole("region", { name: "Approvals" });
  await user.click(within(approvals).getByRole("button", { name: "Review" }));
  const approve = screen.getByRole("button", { name: "Approve" });
  await user.type(screen.getByLabelText("Code shown on New Mac"), "0a1b-2c3d-4e5");
  expect(approve).toBeDisabled();
  await user.type(screen.getByLabelText("Code shown on New Mac"), "f");
  await user.click(approve);
  expect(api.approveDevice).toHaveBeenCalledWith("d2", "0a1b-2c3d-4e5f");
});

test("the Emergency Kit asks for the password when it was not entered lately", async () => {
  const user = userEvent.setup();
  vi.mocked(api.emergencyKit)
    .mockRejectedValueOnce({ kind: "passwordRequired", message: "Enter your master password" })
    .mockResolvedValueOnce(kit);
  render(<SyncDialog onClose={vi.fn()} />);
  await user.click(await screen.findByRole("button", { name: "Emergency Kit…" }));
  await user.type(await screen.findByLabelText("Master password for the Emergency Kit"), "correct horse battery");
  await user.click(screen.getByRole("button", { name: "Show" }));
  expect(api.emergencyKit).toHaveBeenLastCalledWith("correct horse battery");
  expect(await screen.findByTestId("secret-key")).toHaveTextContent("A3KX");
});

test("verify, folder files and the log", async () => {
  const user = userEvent.setup();
  vi.mocked(api.verifySync).mockResolvedValue({
    items: 12,
    damaged: 0,
    attachments: 2,
    damagedAttachments: 0,
    differing: [],
    missing: 0,
  });
  vi.mocked(api.syncFolderFiles).mockResolvedValue([
    { path: "streams/0101/0000000000000001.seg", size: 2048, counted: true },
    { path: "streams/0101/x (1).seg", size: 10, counted: false },
  ]);
  render(<SyncDialog onClose={vi.fn()} />);
  await user.click(await screen.findByRole("button", { name: "Verify everything" }));
  expect(await screen.findByRole("status", { name: "Verify" })).toHaveTextContent("12 item(s) and 2 attachment(s) checked. Everything matches.");
  await user.click(screen.getByRole("button", { name: "What the folder sees" }));
  const table = await screen.findByRole("table", { name: "Folder files" });
  expect(within(table).getByText("2.0 KB")).toBeInTheDocument();
  expect(within(table).getByText("unknown, ignored")).toBeInTheDocument();
  expect(screen.getByText(/Received 2 change\(s\) from Laptop/)).toBeInTheDocument();
});

test("turning sync off and starting a new account", async () => {
  const user = userEvent.setup();
  vi.mocked(api.disableSync).mockResolvedValue(undefined);
  vi.mocked(api.startNewSyncAccount).mockResolvedValue(kit);
  render(<SyncDialog onClose={vi.fn()} />);
  await user.click(await screen.findByRole("button", { name: "Turn off sync" }));
  await user.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: "Turn off sync" }));
  expect(api.disableSync).toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Start a new account…" }));
  const dialog = screen.getByRole("alertdialog");
  expect(within(dialog).getByText(/a device was stolen/)).toBeInTheDocument();
  await user.type(within(dialog).getByLabelText("Master password"), "correct horse battery");
  await user.click(within(dialog).getByRole("button", { name: "Start a new account" }));
  expect(api.startNewSyncAccount).toHaveBeenCalledWith("correct horse battery");
  expect(await screen.findByRole("region", { name: "Emergency Kit" })).toBeInTheDocument();
});

test("backup copies can be deleted", async () => {
  const user = userEvent.setup();
  vi.mocked(api.backups).mockResolvedValue([
    { name: "keyorra.db.bak-v1", size: 4096, modified: 1_790_000_000, kind: "migration" },
  ]);
  vi.mocked(api.deleteBackup).mockResolvedValue(undefined);
  render(<SyncDialog onClose={vi.fn()} />);
  const backups = await screen.findByRole("region", { name: "Backups" });
  expect(within(backups).getByText(/Before an upgrade/)).toBeInTheDocument();
  await user.click(within(backups).getByRole("button", { name: "Delete" }));
  await user.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: "Delete" }));
  await waitFor(() => expect(api.deleteBackup).toHaveBeenCalledWith("keyorra.db.bak-v1"));
});
```

- [ ] **Step 2: Implement.**

Create `app/src/components/SyncDialog.tsx`:

```tsx
import { open } from "@tauri-apps/plugin-dialog";
import { useCallback, useEffect, useState, type FormEvent } from "react";
import {
  api,
  errorMessage,
  isCmdError,
  type AlarmAction,
  type BackupFile,
  type EmergencyKit as Kit,
  type FolderFile,
  type JoinOutcome,
  type SyncDevice,
  type SyncPlace,
  type SyncScreen,
  type VerifyReport,
} from "../api";
import { ApproveDialog } from "./ApproveDialog";
import { ConfirmDialog } from "./ConfirmDialog";
import { EmergencyKit } from "./EmergencyKit";
import { IconClose } from "./icons";
import { JoinResult, JoinSync } from "./JoinSync";

export const ACTION_LABEL: Record<AlarmAction, string> = {
  accept: "Accept",
  restore: "Restore from this Mac",
  remove: "Remove device",
  leave: "Continue as a new device",
};

export function formatTime(secs: number) {
  return new Date(secs * 1000).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function formatSize(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

/** Settings → Sync: turning sync on or joining, and everything about a synced account. */
export function SyncDialog({ onClose, onChanged }: { onClose: () => void; onChanged?: () => void }) {
  const [screen, setScreen] = useState<SyncScreen | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [kit, setKit] = useState<Kit | null>(null);
  const [joined, setJoined] = useState<JoinOutcome | null>(null);

  const load = useCallback(
    () =>
      api
        .syncScreen()
        .then((s) => {
          setScreen(s);
          setError(null);
        })
        .catch((e) => setError(errorMessage(e))),
    [],
  );
  useEffect(() => {
    void load();
    const unlisten = api.onSynced(() => void load());
    return () => {
      unlisten.then((stop) => stop());
    };
  }, [load]);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const changed = () => {
    void load();
    onChanged?.();
  };

  return (
    <div className="modal-backdrop">
      <div className="card modal sync" role="dialog" aria-modal="true" aria-labelledby="sync-title">
        <header className="modal-header">
          <h2 id="sync-title">Sync</h2>
          <button className="icon" aria-label="Close" onClick={onClose}>
            <IconClose />
          </button>
        </header>
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        {kit ? (
          <EmergencyKit
            kit={kit}
            location={screen?.location ?? null}
            onDone={() => {
              setKit(null);
              changed();
            }}
          />
        ) : joined ? (
          <JoinResult
            outcome={joined}
            onDone={() => {
              setJoined(null);
              changed();
            }}
          />
        ) : screen === null ? (
          <p className="muted">Loading…</p>
        ) : screen.enabled ? (
          <SyncOn screen={screen} onKit={setKit} onChanged={changed} />
        ) : (
          <SyncOff onKit={setKit} onJoined={setJoined} />
        )}
      </div>
    </div>
  );
}

function SyncOff({ onKit, onJoined }: { onKit: (kit: Kit) => void; onJoined: (o: JoinOutcome) => void }) {
  const [place, setPlace] = useState<SyncPlace | null>(null);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [joining, setJoining] = useState(false);
  useEffect(() => {
    api
      .syncPlace()
      .then(setPlace)
      .catch(() => setPlace(null));
  }, []);

  async function choose(path: string | null) {
    setError(null);
    try {
      setPlace(await api.setSyncPlace(path));
    } catch (e) {
      setError(errorMessage(e));
    }
  }
  async function chooseFolder() {
    const picked = await open({ directory: true, multiple: false, title: "Where Keyorra keeps synced accounts" });
    if (typeof picked === "string") await choose(picked);
  }
  async function enable(e: FormEvent) {
    e.preventDefault();
    if (!password || busy) return;
    setBusy(true);
    setError(null);
    try {
      onKit(await api.enableSync(password));
    } catch (err) {
      setError(isCmdError(err) && err.kind === "wrongPassword" ? "The master password is wrong" : errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  if (joining) {
    return (
      <section className="modal-section">
        <h3>Join a synced account</h3>
        <JoinSync onJoined={onJoined} onCancel={() => setJoining(false)} />
      </section>
    );
  }
  return (
    <>
      <section className="modal-section">
        <h3>Where</h3>
        {place ? (
          <>
            <p className="mono">{place.path}</p>
            {place.warning && <p className="muted">{place.warning}</p>}
          </>
        ) : (
          <p className="muted">iCloud Drive isn't set up on this Mac. Choose a folder that a sync app keeps in step.</p>
        )}
        <div className="modal-actions">
          {place && place.kind !== "icloud" && (
            <button className="secondary" onClick={() => choose(null)}>
              Use iCloud Drive
            </button>
          )}
          <button className="secondary" onClick={chooseFolder}>
            Choose another folder…
          </button>
        </div>
      </section>
      <form className="modal-section" onSubmit={enable}>
        <h3>Turn on sync</h3>
        <p className="muted">
          This Mac becomes your main Mac: it approves the devices that join. You get an Emergency Kit to print.
        </p>
        <label>
          Master password
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </label>
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        <div className="modal-actions">
          <button type="submit" className="primary" disabled={!password || busy || !place}>
            {busy ? "Turning on…" : "Turn on sync"}
          </button>
        </div>
      </form>
      <section className="modal-section">
        <h3>Already syncing on another Mac?</h3>
        <div className="modal-actions">
          <button className="secondary" onClick={() => setJoining(true)}>
            Join a synced account…
          </button>
        </div>
      </section>
    </>
  );
}

function SyncOn({
  screen,
  onKit,
  onChanged,
}: {
  screen: SyncScreen;
  onKit: (kit: Kit) => void;
  onChanged: () => void;
}) {
  const status = screen.status;
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [approving, setApproving] = useState<SyncDevice | null>(null);
  const [removing, setRemoving] = useState<SyncDevice | null>(null);
  const [turningOff, setTurningOff] = useState(false);
  const [startingOver, setStartingOver] = useState(false);
  const [kitPassword, setKitPassword] = useState<string | null>(null);
  const [files, setFiles] = useState<FolderFile[] | null>(null);
  const [report, setReport] = useState<VerifyReport | null>(null);
  const [backups, setBackups] = useState<BackupFile[]>([]);
  const [deleting, setDeleting] = useState<BackupFile | null>(null);

  const loadBackups = useCallback(
    () =>
      api
        .backups()
        .then(setBackups)
        .catch(() => setBackups([])),
    [],
  );
  useEffect(() => {
    void loadBackups();
  }, [loadBackups]);

  async function run(action: () => Promise<unknown>) {
    setBusy(true);
    setError(null);
    try {
      await action();
      onChanged();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }
  async function openKit(password: string | null) {
    setError(null);
    try {
      onKit(await api.emergencyKit(password));
      setKitPassword(null);
    } catch (e) {
      if (isCmdError(e) && e.kind === "passwordRequired") setKitPassword("");
      else setError(isCmdError(e) && e.kind === "wrongPassword" ? "The master password is wrong" : errorMessage(e));
    }
  }

  const waiting = status?.devices.filter((d) => !d.approved) ?? [];
  return (
    <>
      <section className="modal-section" aria-label="Sync status">
        <h3>Status</h3>
        {screen.error ? (
          <p className="error" role="alert">
            {screen.error}
          </p>
        ) : (
          <p>
            {screen.lastRoundAt
              ? `${screen.lastRoundOk ? "Synced" : "Sync failed"} ${formatTime(screen.lastRoundAt)}`
              : "Not synced yet in this session"}
          </p>
        )}
        {screen.location && <p className="mono muted">{screen.location}</p>}
        {status?.waitingForApproval && (
          <p>
            This Mac waits for your main Mac to approve it. The main Mac must see this code:{" "}
            <span className="mono">{status.keyCode}</span>
          </p>
        )}
        {status && !status.mainDevice && !status.rootConfirmed && (
          <p className="muted">Changes from other devices aren't confirmed by your main Mac yet.</p>
        )}
        <div className="modal-actions">
          <button className="secondary" disabled={busy} onClick={() => run(api.syncNow)}>
            Sync now
          </button>
        </div>
      </section>

      {status?.mainDevice && waiting.length > 0 && (
        <section className="modal-section" aria-label="Approvals">
          <h3>Waiting for approval</h3>
          <ul className="sync-list">
            {waiting.map((d) => (
              <li key={d.id}>
                <span>{d.name}</span>
                <button className="primary" onClick={() => setApproving(d)}>
                  Review
                </button>
              </li>
            ))}
          </ul>
        </section>
      )}

      {screen.alarms.length > 0 && (
        <section className="modal-section" aria-label="Alarms">
          <h3>Needs your attention</h3>
          <ul className="sync-alarms">
            {screen.alarms.map((a) => (
              <li key={a.id}>
                <strong>{a.title}</strong>
                <p className="muted">{a.explanation}</p>
                <div className="modal-actions">
                  {a.actions.map((action) => (
                    <button
                      key={action}
                      className={action === "accept" ? "secondary" : "primary"}
                      disabled={busy}
                      onClick={() => run(() => api.syncAlarmAction(a.id, action))}
                    >
                      {ACTION_LABEL[action]}
                    </button>
                  ))}
                </div>
              </li>
            ))}
          </ul>
        </section>
      )}

      {screen.notices.length > 0 && (
        <section className="modal-section" aria-label="Notices">
          <h3>Notices</h3>
          <ul>
            {screen.notices.map((n, i) => (
              <li key={i} className="muted">
                {n}
              </li>
            ))}
          </ul>
        </section>
      )}

      {status && (
        <section className="modal-section" aria-label="Devices">
          <h3>Devices</h3>
          <ul className="sync-list">
            {status.devices.map((d) => (
              <li key={d.id}>
                <span>
                  {d.name}
                  {d.main && <span className="chip">Main Mac</span>}
                  {d.thisDevice && <span className="chip">This Mac</span>}
                  {!d.approved && <span className="chip">Waiting</span>}
                  {d.removed && <span className="chip">Removed</span>}
                </span>
                {status.mainDevice && !d.thisDevice && d.approved && !d.removed && (
                  <button className="secondary" onClick={() => setRemoving(d)}>
                    Remove
                  </button>
                )}
              </li>
            ))}
          </ul>
        </section>
      )}

      <section className="modal-section" aria-label="Tools">
        <h3>Tools</h3>
        {kitPassword !== null && (
          <form
            className="row"
            onSubmit={(e) => {
              e.preventDefault();
              void openKit(kitPassword);
            }}
          >
            <label>
              Master password for the Emergency Kit
              <input type="password" autoFocus value={kitPassword} onChange={(e) => setKitPassword(e.target.value)} />
            </label>
            <button type="submit" className="primary" disabled={!kitPassword}>
              Show
            </button>
          </form>
        )}
        <div className="modal-actions">
          <button className="secondary" onClick={() => openKit(null)}>
            Emergency Kit…
          </button>
          <button className="secondary" onClick={() => run(async () => setReport(await api.verifySync()))}>
            Verify everything
          </button>
          <button className="secondary" onClick={() => run(async () => setFiles(await api.syncFolderFiles()))}>
            What the folder sees
          </button>
        </div>
        {report && (
          <p role="status" aria-label="Verify">
            {report.items} item(s) and {report.attachments} attachment(s) checked.{" "}
            {report.damaged + report.damagedAttachments + report.differing.length + report.missing === 0
              ? "Everything matches."
              : [
                  report.damaged && `${report.damaged} unreadable`,
                  report.damagedAttachments && `${report.damagedAttachments} unreadable attachment(s)`,
                  report.differing.length && `differs from sync: ${report.differing.join(", ")}`,
                  report.missing && `${report.missing} not here yet`,
                ]
                  .filter(Boolean)
                  .join("; ")}
          </p>
        )}
        {files && (
          <table className="folder-files" aria-label="Folder files">
            <tbody>
              {files.map((f) => (
                <tr key={f.path} className={f.counted ? undefined : "unknown"}>
                  <td className="mono">{f.path}</td>
                  <td>{formatSize(f.size)}</td>
                  <td>{f.counted ? "" : "unknown, ignored"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {backups.length > 0 && (
        <section className="modal-section" aria-label="Backups">
          <h3>Copies of your vault on this Mac</h3>
          <p className="muted">Kept when the vault was upgraded or replaced by joining an account. You can delete them.</p>
          <ul className="sync-list">
            {backups.map((b) => (
              <li key={b.name}>
                <span>
                  {b.kind === "migration" ? "Before an upgrade" : "Before joining an account"} ·{" "}
                  {formatTime(b.modified)} · {formatSize(b.size)}
                </span>
                <button className="secondary" onClick={() => setDeleting(b)}>
                  Delete
                </button>
              </li>
            ))}
          </ul>
        </section>
      )}

      <section className="modal-section" aria-label="Log">
        <details>
          <summary>Sync log</summary>
          {screen.log.length === 0 ? (
            <p className="muted">Nothing yet in this session.</p>
          ) : (
            <ul className="sync-log">
              {screen.log.map((l, i) => (
                <li key={i}>
                  <span className="muted">{formatTime(l.at)}</span> {l.text}
                </li>
              ))}
            </ul>
          )}
        </details>
      </section>

      <section className="modal-section" aria-label="Leave">
        <h3>Turn off or start over</h3>
        <div className="modal-actions">
          <button className="secondary" onClick={() => setTurningOff(true)}>
            Turn off sync
          </button>
          {status?.mainDevice && (
            <button className="danger" onClick={() => setStartingOver(true)}>
              Start a new account…
            </button>
          )}
        </div>
      </section>

      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}

      {approving && (
        <ApproveDialog
          device={approving}
          onDone={() => {
            setApproving(null);
            onChanged();
          }}
        />
      )}
      {removing && (
        <ConfirmDialog
          title={`Remove “${removing.name}”?`}
          confirmLabel="Remove device"
          danger
          focusCancel
          onCancel={() => setRemoving(null)}
          onConfirm={() => {
            const d = removing;
            setRemoving(null);
            void run(() => api.removeSyncDevice(d.id));
          }}
        >
          It can no longer read what is written from now on. What it already has stays on it: if it was stolen,
          change your master password and consider starting a new account.
        </ConfirmDialog>
      )}
      {turningOff && (
        <ConfirmDialog
          title="Turn off sync on this Mac?"
          confirmLabel="Turn off sync"
          focusCancel
          onCancel={() => setTurningOff(false)}
          onConfirm={() => {
            setTurningOff(false);
            void run(api.disableSync);
          }}
        >
          Everything stays in this vault. You can join the account again later; changes made meanwhile are merged.
        </ConfirmDialog>
      )}
      {deleting && (
        <ConfirmDialog
          title="Delete this copy?"
          confirmLabel="Delete"
          danger
          focusCancel
          onCancel={() => setDeleting(null)}
          onConfirm={() => {
            const b = deleting;
            setDeleting(null);
            void run(async () => {
              await api.deleteBackup(b.name);
              await loadBackups();
            });
          }}
        >
          It is an older copy of your vault, encrypted with your master password at that time.
        </ConfirmDialog>
      )}
      {startingOver && (
        <StartOverDialog
          onCancel={() => setStartingOver(false)}
          onStarted={(k) => {
            setStartingOver(false);
            onKit(k);
          }}
        />
      )}
    </>
  );
}

/**
 * Starting a new account from the main Mac: for a stolen or copied main Mac, or to cut every
 * other device off. New keys for everything; the other Macs join the new account.
 */
function StartOverDialog({ onCancel, onStarted }: { onCancel: () => void; onStarted: (kit: Kit) => void }) {
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function start(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      onStarted(await api.startNewSyncAccount(password));
    } catch (err) {
      setError(isCmdError(err) && err.kind === "wrongPassword" ? "The master password is wrong" : errorMessage(err));
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="modal-backdrop">
      <form className="card modal confirm" role="alertdialog" aria-modal="true" aria-labelledby="restart-title" onSubmit={start}>
        <h2 id="restart-title">Start a new account?</h2>
        <div className="muted">
          <p>
            Use this if a device was stolen, if this Mac was copied, or to cut every other device off. Every key of
            your vault is replaced, and this Mac starts a new account in a new folder with a new Secret Key.
          </p>
          <p>
            Your other Macs keep what they have but get nothing new. Join them to the new account with its setup code.
            Delete the old account's folder afterwards so nobody reads it. Touch ID turns off; turn it on again in
            Settings.
          </p>
        </div>
        <label>
          Master password
          <input type="password" autoFocus value={password} onChange={(e) => setPassword(e.target.value)} />
        </label>
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        <div className="modal-actions">
          <button type="button" onClick={onCancel} disabled={busy}>
            Cancel
          </button>
          <button type="submit" className="danger" disabled={!password || busy}>
            Start a new account
          </button>
        </div>
      </form>
    </div>
  );
}
```

- [ ] **Step 3: Run and commit.**

Commit: `App A3-2: the Sync screen`.

---

### Task 4: The banner, Settings, first run, styles

**Files:** Create `app/src/components/SyncBanner.tsx`, `SyncBanner.test.tsx`; modify `Main.tsx`, `SettingsDialog.tsx`, `Setup.tsx`, `Main.test.tsx`, `Setup.test.tsx`, `app/src/App.test.tsx`, `app/src/styles.css`.

- [ ] **Step 1: Failing tests.**

Create `app/src/components/SyncBanner.test.tsx`:

```tsx
import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { api } from "../api";
import { syncScreen } from "../test/sync";
import { SyncBanner } from "./SyncBanner";

vi.mock("../api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api")>();
  return {
    ...actual,
    api: { ...actual.api, syncScreen: vi.fn(), onSynced: vi.fn(), onSyncApproval: vi.fn() },
  };
});

let synced: (() => void) | null = null;
beforeEach(() => {
  synced = null;
  vi.mocked(api.onSynced).mockReset().mockImplementation(async (cb) => {
    synced = cb;
    return () => {};
  });
  vi.mocked(api.onSyncApproval).mockReset().mockResolvedValue(() => {});
});

test("nothing while all is well", async () => {
  vi.mocked(api.syncScreen).mockReset().mockResolvedValue(syncScreen());
  const { container } = render(<SyncBanner onOpen={vi.fn()} />);
  await act(async () => {});
  expect(container).toBeEmptyDOMElement();
});

test("devices waiting for approval, after a round", async () => {
  const user = userEvent.setup();
  const waiting = syncScreen();
  waiting.status!.devices.push({ id: "d2", name: "New Mac", approved: false, main: false, thisDevice: false, removed: false });
  vi.mocked(api.syncScreen).mockReset().mockResolvedValueOnce(syncScreen()).mockResolvedValue(waiting);
  const onOpen = vi.fn();
  const onSynced = vi.fn();
  render(<SyncBanner onOpen={onOpen} onSynced={onSynced} />);
  await act(async () => synced?.());
  expect(onSynced).toHaveBeenCalled();
  expect(await screen.findByRole("status")).toHaveTextContent("1 device asked to join your account");
  await user.click(screen.getByRole("button", { name: "Review" }));
  expect(onOpen).toHaveBeenCalled();
});

test("changes not yet confirmed by the main Mac", async () => {
  const s = syncScreen();
  s.status = { ...s.status!, mainDevice: false, rootConfirmed: false };
  vi.mocked(api.syncScreen).mockReset().mockResolvedValue(s);
  render(<SyncBanner onOpen={vi.fn()} />);
  expect(await screen.findByRole("status")).toHaveTextContent("aren't confirmed by your main Mac yet");
});
```

Apply (the first run offers joining; the screens that render `Main` mock the new calls):

```diff
diff --git a/app/src/App.test.tsx b/app/src/App.test.tsx
index 5fa5911..b8a8b58 100644
--- a/app/src/App.test.tsx
+++ b/app/src/App.test.tsx
@@ -19,6 +19,9 @@ vi.mock("./api", async (importOriginal) => {
       onUnlocked: vi.fn(),
       onPairRequest: vi.fn().mockResolvedValue(() => {}),
       onItemsChanged: vi.fn().mockResolvedValue(() => {}),
+      syncScreen: vi.fn().mockRejectedValue({ kind: "locked", message: "locked" }),
+      onSynced: vi.fn().mockResolvedValue(() => {}),
+      onSyncApproval: vi.fn().mockResolvedValue(() => {}),
     },
   };
 });
diff --git a/app/src/components/Main.test.tsx b/app/src/components/Main.test.tsx
index 3473e79..645d957 100644
--- a/app/src/components/Main.test.tsx
+++ b/app/src/components/Main.test.tsx
@@ -29,6 +29,9 @@ vi.mock("../api", async (importOriginal) => {
       settings: vi.fn(),
       onPairRequest: vi.fn(),
       onItemsChanged: vi.fn(),
+      syncScreen: vi.fn(),
+      onSynced: vi.fn(),
+      onSyncApproval: vi.fn(),
     },
   };
 });
@@ -42,6 +45,12 @@ const github: ItemSummary = {
 };
 
 beforeEach(() => {
+  vi.mocked(api.syncScreen).mockReset().mockResolvedValue({
+    enabled: false, running: false, error: null, location: null, lastRoundAt: null,
+    lastRoundOk: null, status: null, alarms: [], notices: [], log: [],
+  });
+  vi.mocked(api.onSynced).mockReset().mockResolvedValue(() => {});
+  vi.mocked(api.onSyncApproval).mockReset().mockResolvedValue(() => {});
   pairCallback = null;
   changedCallback = null;
   vi.mocked(api.onItemsChanged)
diff --git a/app/src/components/Setup.test.tsx b/app/src/components/Setup.test.tsx
index d5c6803..47a7454 100644
--- a/app/src/components/Setup.test.tsx
+++ b/app/src/components/Setup.test.tsx
@@ -6,11 +6,12 @@ import { Setup } from "./Setup";
 
 vi.mock("../api", async (importOriginal) => {
   const actual = await importOriginal<typeof import("../api")>();
-  return { ...actual, api: { ...actual.api, create: vi.fn() } };
+  return { ...actual, api: { ...actual.api, create: vi.fn(), joinSync: vi.fn() } };
 });
 
 beforeEach(() => {
   vi.mocked(api.create).mockReset();
+  vi.mocked(api.joinSync).mockReset();
 });
 
 test("creates the vault once both passwords match and are long enough", async () => {
@@ -44,3 +45,23 @@ test("shows a backend error", async () => {
   await user.click(screen.getByRole("button", { name: "Create vault" }));
   expect(await screen.findByRole("alert")).toHaveTextContent("A vault already exists on this Mac");
 });
+
+test("a new Mac can join a synced account instead", async () => {
+  const user = userEvent.setup();
+  const onDone = vi.fn();
+  vi.mocked(api.joinSync).mockResolvedValue({
+    mode: "new",
+    keyCode: "0a1b-2c3d-4e5f",
+    copied: 0,
+    trashedLeft: 0,
+    damaged: 0,
+  });
+  render(<Setup onDone={onDone} />);
+  await user.click(screen.getByRole("button", { name: /Join your synced account/ }));
+  await user.type(screen.getByLabelText("Master password"), "correct horse battery");
+  await user.type(screen.getByLabelText("Setup code or Secret Key"), "KEYORRA-SETUP-1-XYZ");
+  await user.click(screen.getByRole("button", { name: "Join" }));
+  expect(await screen.findByTestId("key-code")).toHaveTextContent("0a1b-2c3d-4e5f");
+  await user.click(screen.getByRole("button", { name: "Continue" }));
+  expect(onDone).toHaveBeenCalled();
+});
```

- [ ] **Step 2: Banner.**

Create `app/src/components/SyncBanner.tsx`:

```tsx
import { useEffect, useState } from "react";
import { api, type SyncScreen } from "../api";

/**
 * Above the item list: devices waiting for the main Mac's approval, sync that stopped, and
 * changes not yet confirmed by the main Mac. Refreshes on every round.
 */
export function SyncBanner({ onOpen, onSynced }: { onOpen: () => void; onSynced?: () => void }) {
  const [screen, setScreen] = useState<SyncScreen | null>(null);
  useEffect(() => {
    const load = () =>
      api
        .syncScreen()
        .then(setScreen)
        .catch(() => setScreen(null));
    void load();
    const subscriptions = [
      api.onSynced(() => {
        void load();
        onSynced?.();
      }),
      api.onSyncApproval(() => void load()),
    ];
    return () => {
      subscriptions.forEach((p) => p.then((stop) => stop()));
    };
  }, [onSynced]);

  if (!screen?.enabled) return null;
  const status = screen.status;
  const waiting = status?.mainDevice ? status.devices.filter((d) => !d.approved).length : 0;
  const message =
    waiting > 0
      ? `${waiting} device${waiting === 1 ? "" : "s"} asked to join your account`
      : screen.alarms.length > 0
        ? "Sync needs your attention"
        : screen.error
          ? `Sync stopped: ${screen.error}`
          : status && !status.mainDevice && !status.rootConfirmed
            ? "Changes from other devices aren't confirmed by your main Mac yet"
            : null;
  if (!message) return null;
  return (
    <div className="banner sync-banner" role="status">
      {message}
      <button onClick={onOpen}>{waiting > 0 ? "Review" : "Open Sync"}</button>
    </div>
  );
}
```

- [ ] **Step 3: Wiring and styles.**

Apply:

```diff
diff --git a/app/src/components/Main.tsx b/app/src/components/Main.tsx
index e1926e0..9ba8cf8 100644
--- a/app/src/components/Main.tsx
+++ b/app/src/components/Main.tsx
@@ -17,6 +17,8 @@ import { PairingDialog } from "./PairingDialog";
 import { ItemList } from "./ItemList";
 import { TrashItem } from "./TrashItem";
 import { SettingsDialog } from "./SettingsDialog";
+import { SyncBanner } from "./SyncBanner";
+import { SyncDialog } from "./SyncDialog";
 import { Sidebar, type Selection } from "./Sidebar";
 import { Watchtower } from "./Watchtower";
 
@@ -30,6 +32,7 @@ export function Main({ onLock }: { onLock: () => void }) {
   const [pane, setPane] = useState<Pane>({ mode: "empty" });
   const [importing, setImporting] = useState(false);
   const [showSettings, setShowSettings] = useState(false);
+  const [showSync, setShowSync] = useState(false);
   const [error, setError] = useState<string | null>(null);
   const [pairing, setPairing] = useState<PairingRequest | null>(null);
   const [report, setReport] = useState<WatchtowerReport | null>(null);
@@ -239,6 +242,7 @@ export function Main({ onLock }: { onLock: () => void }) {
         />
       )}
       <section className="detail">
+        <SyncBanner onOpen={() => setShowSync(true)} onSynced={refresh} />
         {error && (
           <div className="banner error" role="alert">
             {error}
@@ -282,7 +286,16 @@ export function Main({ onLock }: { onLock: () => void }) {
         )}
       </section>
       {importing && <ImportDialog onClose={() => setImporting(false)} onImported={refresh} />}
-      {showSettings && <SettingsDialog onClose={() => setShowSettings(false)} />}
+      {showSettings && (
+        <SettingsDialog
+          onClose={() => setShowSettings(false)}
+          onOpenSync={() => {
+            setShowSettings(false);
+            setShowSync(true);
+          }}
+        />
+      )}
+      {showSync && <SyncDialog onClose={() => setShowSync(false)} onChanged={() => void refresh()} />}
       {deletingVault && (
         <ConfirmDialog
           title={`Delete vault "${deletingVault.name}"?`}
diff --git a/app/src/components/SettingsDialog.tsx b/app/src/components/SettingsDialog.tsx
index de50a35..3aed295 100644
--- a/app/src/components/SettingsDialog.tsx
+++ b/app/src/components/SettingsDialog.tsx
@@ -11,7 +11,7 @@ function withCurrent(options: number[], value: number) {
   return options.includes(value) ? options : [...options, value].sort((a, b) => a - b);
 }
 
-export function SettingsDialog({ onClose }: { onClose: () => void }) {
+export function SettingsDialog({ onClose, onOpenSync }: { onClose: () => void; onOpenSync?: () => void }) {
   const [theme, setTheme] = useState<Theme>(loadTheme);
   const [settings, setSettings] = useState<Settings | null>(null);
   const [saved, setSaved] = useState(false);
@@ -183,6 +183,18 @@ export function SettingsDialog({ onClose }: { onClose: () => void }) {
           )}
         </section>
 
+        {onOpenSync && (
+          <section className="modal-section">
+            <h3>Sync</h3>
+            <p className="muted">Keep this vault in step across your Macs through iCloud Drive or a folder you choose.</p>
+            <div className="modal-actions">
+              <button className="secondary" onClick={onOpenSync}>
+                Sync settings…
+              </button>
+            </div>
+          </section>
+        )}
+
         <section className="modal-section">
           <h3>Touch ID</h3>
           {touchId && !touchId.available && <p className="muted">Touch ID isn't available on this Mac.</p>}
diff --git a/app/src/components/Setup.tsx b/app/src/components/Setup.tsx
index baac0d9..21c09ea 100644
--- a/app/src/components/Setup.tsx
+++ b/app/src/components/Setup.tsx
@@ -1,6 +1,7 @@
 import { Keyhole } from "./Keyhole";
 import { useState, type FormEvent } from "react";
-import { api, errorMessage } from "../api";
+import { api, errorMessage, type JoinOutcome } from "../api";
+import { JoinResult, JoinSync } from "./JoinSync";
 
 const MIN_LENGTH = 10;
 
@@ -9,6 +10,8 @@ export function Setup({ onDone }: { onDone: () => void }) {
   const [confirm, setConfirm] = useState("");
   const [error, setError] = useState<string | null>(null);
   const [busy, setBusy] = useState(false);
+  const [joining, setJoining] = useState(false);
+  const [joined, setJoined] = useState<JoinOutcome | null>(null);
   const tooShort = password.length > 0 && password.length < MIN_LENGTH;
   const mismatch = confirm.length > 0 && confirm !== password;
   const valid = password.length >= MIN_LENGTH && confirm === password;
@@ -28,6 +31,24 @@ export function Setup({ onDone }: { onDone: () => void }) {
     }
   }
 
+  if (joining) {
+    return (
+      <div className="center">
+        <div className="card auth">
+          <div className="logo">
+            <Keyhole width={24} height={24} />
+          </div>
+          <h1>Join a synced account</h1>
+          {joined ? (
+            <JoinResult outcome={joined} onDone={onDone} />
+          ) : (
+            <JoinSync onJoined={setJoined} onCancel={() => setJoining(false)} />
+          )}
+        </div>
+      </div>
+    );
+  }
+
   return (
     <div className="center">
       <form className="card auth" onSubmit={submit}>
@@ -56,6 +77,9 @@ export function Setup({ onDone }: { onDone: () => void }) {
         <button className="primary" type="submit" disabled={!valid || busy}>
           {busy ? "Creating…" : "Create vault"}
         </button>
+        <button type="button" className="link" onClick={() => setJoining(true)}>
+          Already use Keyorra on another Mac? Join your synced account
+        </button>
       </form>
     </div>
   );
diff --git a/app/src/styles.css b/app/src/styles.css
index 592a01a..8a9fa72 100644
--- a/app/src/styles.css
+++ b/app/src/styles.css
@@ -296,3 +296,29 @@ fieldset.fields .reveal { align-self: flex-start; }
 .quick-search .hints { color: var(--muted); font-size: 11px; padding: 8px 14px; border-top: 1px solid var(--line); }
 
 .auth code.path { display: block; word-break: break-all; font-size: 12px; user-select: text; }
+
+/* Sync (plan A3) */
+.modal.sync { max-width: 640px; }
+.sync-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 8px; }
+.sync-list li { display: flex; justify-content: space-between; align-items: center; gap: 12px; }
+.sync-list .chip { margin-left: 8px; }
+.sync-alarms { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 12px; }
+.sync-alarms li { border: 1px solid var(--line); border-radius: var(--r-card); padding: 12px 14px; background: var(--surface); }
+.sync-log { list-style: none; margin: 8px 0 0; padding: 0; max-height: 200px; overflow: auto; font-size: 12px; display: flex; flex-direction: column; gap: 4px; }
+.folder-files { width: 100%; border-collapse: collapse; font-size: 12px; margin-top: 8px; }
+.folder-files td { padding: 3px 6px; border-bottom: 1px solid var(--line); }
+.folder-files tr.unknown td { color: var(--danger); }
+.sync-banner { background: var(--brand-soft); color: var(--text); font-weight: 600; }
+.kit-sheet { display: grid; grid-template-columns: max-content 1fr; gap: 6px 16px; margin: 12px 0; }
+.kit-sheet dt { color: var(--muted); font-weight: 600; }
+.kit-sheet dd { margin: 0; word-break: break-all; }
+.kit-blank { border-bottom: 1px solid var(--line-strong); min-height: 1.6em; }
+.join-sync, .join-result { display: flex; flex-direction: column; gap: 12px; }
+button.link { background: none; border: none; color: var(--brand); padding: 4px 0; font-weight: 600; cursor: pointer; }
+
+@media print {
+  body * { visibility: hidden; }
+  .kit, .kit * { visibility: visible; }
+  .kit { position: absolute; inset: 0; padding: 24px; background: white; color: black; }
+  .kit .modal-actions, .kit .status { display: none; }
+}
```

- [ ] **Step 4: Run and commit.**

`pnpm exec tsc --noEmit`; `pnpm exec vitest run` (126 passed when verified). Commit: `App A3-2: sync banner, Settings → Sync, joining on first run`.

---

### Task 5: Spec, and by hand

**Files:** Modify `docs/superpowers/specs/2026-10-05-keyorra-sync-design.md`.

- [ ] **Step 1: Apply the "Spec changes" above.**

Commit: `docs: A3-2 Sync screen and flows`.

- [ ] **Step 2: By hand (two Macs, one iCloud account; not automated).**

`pnpm tauri dev` on both. Mac 1: Settings → Sync → Turn on sync, print the kit, copy the setup code. Mac 2 (new user account or second Mac): first run → Join your synced account → paste the code → note the code shown. Mac 1: the banner asks to review; type the code; approve. Add an item with an attachment on Mac 2; it appears on Mac 1. Check the Sync screen's tools, then turn sync off on Mac 2 and join again.

---

### Task 6: Final verification

**Files:** —

- [ ] **Step 1: Run.**

From `app/`: `pnpm exec tsc --noEmit`; `pnpm exec vitest run`. From the root: `cargo test --workspace` (687 passed, 4 ignored).

- [ ] **Step 2: Check.**

`git status` clean apart from untracked files that are not part of this plan (`site/`); no push.

---

