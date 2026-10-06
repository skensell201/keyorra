import { useCallback, useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import {
  api,
  errorMessage,
  isCmdError,
  type AlarmAction,
  type BackupFile,
  type EmergencyKit as Kit,
  type FolderFile,
  type JoinOutcome,
  type SyncAlarm,
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
import { SyncPlaceChooser } from "./SyncPlaceChooser";

export const ACTION_LABEL: Record<AlarmAction, string> = {
  accept: "Accept",
  restore: "Restore from this Mac",
  remove: "Remove device",
  leave: "Continue as a new device",
};

/** What an alarm action does, asked before it is done (all but "accept" change the account). */
const ACTION_CONFIRM: Record<Exclude<AlarmAction, "accept">, { title: string; body: ReactNode }> = {
  restore: {
    title: "Restore the missing changes from this Mac?",
    body: (
      <>
        This Mac writes the changes that went missing back into the sync folder from its own copy. Do it only if
        nobody meant to roll the folder back.
      </>
    ),
  },
  remove: {
    title: "Remove this device?",
    body: (
      <>
        It can no longer read what is written from now on, and its paused changes are not taken. What it already has
        stays on it. If you do not recognise it, change your master password too.
      </>
    ),
  },
  leave: {
    title: "Continue as a new device?",
    body: (
      <>
        This Mac stops writing under its current identity and asks to join again as a new device. Your main Mac has to
        approve it again, comparing the code shown here.
      </>
    ),
  },
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
  const dialog = useRef<HTMLDivElement>(null);
  // Escape closes Sync only when nothing is under way (review A3 I7): not while the kit is
  // shown, a dialog inside is open, or a command runs.
  const busy = useRef(false);
  const kitShown = useRef(false);
  kitShown.current = kit !== null;
  const onBusy = useCallback((b: boolean) => {
    busy.current = b;
  }, []);

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
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape" || busy.current || kitShown.current) return;
      if (dialog.current?.querySelector('[aria-modal="true"]')) return;
      onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const changed = () => {
    void load();
    onChanged?.();
  };

  return (
    <div className="modal-backdrop">
      <div className="card modal sync" role="dialog" aria-modal="true" aria-labelledby="sync-title" ref={dialog}>
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
          <SyncOn screen={screen} onKit={setKit} onChanged={changed} onBusy={onBusy} />
        ) : (
          <SyncOff onKit={setKit} onJoined={setJoined} onBusy={onBusy} />
        )}
      </div>
    </div>
  );
}

function SyncOff({
  onKit,
  onJoined,
  onBusy,
}: {
  onKit: (kit: Kit) => void;
  onJoined: (o: JoinOutcome) => void;
  onBusy: (busy: boolean) => void;
}) {
  const [place, setPlace] = useState<SyncPlace | null>(null);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [joining, setJoining] = useState(false);
  useEffect(() => onBusy(busy), [busy, onBusy]);
  useEffect(() => () => onBusy(false), [onBusy]);

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
        <JoinSync onJoined={onJoined} onCancel={() => setJoining(false)} onBusy={onBusy} />
      </section>
    );
  }
  return (
    <>
      <SyncPlaceChooser onPlace={setPlace} />
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
  onBusy,
}: {
  screen: SyncScreen;
  onKit: (kit: Kit) => void;
  onChanged: () => void;
  onBusy: (busy: boolean) => void;
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
  const [confirming, setConfirming] = useState<{ alarm: SyncAlarm; action: Exclude<AlarmAction, "accept"> } | null>(
    null,
  );
  useEffect(() => onBusy(busy), [busy, onBusy]);
  useEffect(() => () => onBusy(false), [onBusy]);

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
    setBusy(true);
    try {
      onKit(await api.emergencyKit(password));
      setKitPassword(null);
    } catch (e) {
      // The typed password is not kept after a failure.
      if (isCmdError(e) && e.kind === "passwordRequired") setKitPassword("");
      else {
        setKitPassword((p) => (p === null ? null : ""));
        setError(isCmdError(e) && e.kind === "wrongPassword" ? "The master password is wrong" : errorMessage(e));
      }
    } finally {
      setBusy(false);
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
                <button className="primary" disabled={busy} onClick={() => setApproving(d)}>
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
                      onClick={() =>
                        action === "accept"
                          ? run(() => api.syncAlarmAction(a.id, action))
                          : setConfirming({ alarm: a, action })
                      }
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
                  <button className="secondary" disabled={busy} onClick={() => setRemoving(d)}>
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
            <button type="button" onClick={() => setKitPassword(null)}>
              Cancel
            </button>
            <button type="submit" className="primary" disabled={!kitPassword || busy}>
              Show
            </button>
          </form>
        )}
        <div className="modal-actions">
          <button className="secondary" disabled={busy} onClick={() => openKit(null)}>
            Emergency Kit…
          </button>
          <button
            className="secondary"
            disabled={busy}
            onClick={() => run(async () => setReport(await api.verifySync()))}
          >
            Verify everything
          </button>
          <button
            className="secondary"
            disabled={busy}
            onClick={() => run(async () => setFiles(await api.syncFolderFiles()))}
          >
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
            <thead>
              <tr>
                <th scope="col">Name</th>
                <th scope="col">Size</th>
                <th scope="col">Status</th>
              </tr>
            </thead>
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
                <button className="secondary" disabled={busy} onClick={() => setDeleting(b)}>
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
      {confirming && (
        <ConfirmDialog
          title={ACTION_CONFIRM[confirming.action].title}
          confirmLabel={ACTION_LABEL[confirming.action]}
          danger
          focusCancel
          onCancel={() => setConfirming(null)}
          onConfirm={() => {
            const { alarm, action } = confirming;
            setConfirming(null);
            void run(() => api.syncAlarmAction(alarm.id, action));
          }}
        >
          <p>
            <strong>{confirming.alarm.title}</strong>
          </p>
          <p>{ACTION_CONFIRM[confirming.action].body}</p>
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
