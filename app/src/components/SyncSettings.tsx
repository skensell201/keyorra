import { useCallback, useEffect, useId, useState, type FormEvent, type ReactNode } from "react";
import {
  api,
  errorMessage,
  isCmdError,
  type AlarmAction,
  type BackupFile,
  type EmergencyKit as Kit,
  type FolderFile,
  type JoinOutcome,
  type LogLine,
  type SyncAlarm,
  type SyncDevice,
  type SyncPlace,
  type SyncScreen,
  type VerifyReport,
} from "../api";
import { plural } from "../format";
import { ApproveDialog } from "./ApproveDialog";
import { ConfirmDialog } from "./ConfirmDialog";
import { EmergencyKit } from "./EmergencyKit";
import {
  IconAlert,
  IconArchive,
  IconCheck,
  IconFolder,
  IconLaptop,
  IconLifebuoy,
  IconShieldCheck,
  IconSync,
} from "./icons";
import { JoinResult, JoinSync } from "./JoinSync";
import { PathText } from "./PathText";
import { SyncPlaceChooser } from "./SyncPlaceChooser";
import { tabName, useTabs } from "./tabs";

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
        Its changes stop counting on your other devices, and its paused changes are not taken. It still holds the
        account key, so it can read new changes for as long as it can reach the sync folder. If you do not recognise
        it, also remove its access to the folder (iCloud: sign it out of your Apple ID) and start a new account.
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

export function formatDate(secs: number) {
  return new Date(secs * 1000).toLocaleDateString(undefined, { dateStyle: "medium" });
}

/** A log time: the time of day for today, with the day otherwise. */
export function formatLogTime(secs: number, now = new Date()) {
  const at = new Date(secs * 1000);
  return at.toDateString() === now.toDateString()
    ? at.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" })
    : at.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

export function formatSize(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

/** One row of the log as shown: a line, or the same line repeated in a row. */
export interface LogGroup {
  text: string;
  /** The newest and the oldest time of the run. */
  at: number;
  firstAt: number;
  count: number;
}

/** Newest first; a line repeated one after another is shown once, with how many times. */
export function groupLog(log: LogLine[]): LogGroup[] {
  const groups: LogGroup[] = [];
  for (const line of log) {
    const last = groups[groups.length - 1];
    if (last && last.text === line.text) {
      last.count += 1;
      last.at = line.at;
    } else {
      groups.push({ text: line.text, at: line.at, firstAt: line.at, count: 1 });
    }
  }
  return groups.reverse();
}

export type SyncSection = "overview" | "devices" | "safety" | "advanced";
const SECTIONS: { id: SyncSection; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "devices", label: "Devices" },
  { id: "safety", label: "Safety" },
  { id: "advanced", label: "Advanced" },
];
const SECTION_IDS = SECTIONS.map((s) => s.id);

/** What waits for the user on this Mac: devices to approve (main Mac only) and alarms. */
export function attentionCount(screen: SyncScreen | null) {
  if (!screen?.enabled) return 0;
  const approvals = screen.status?.mainDevice ? screen.status.devices.filter((d) => !d.approved).length : 0;
  return approvals + screen.alarms.length;
}

interface Props {
  section: SyncSection;
  onSection: (section: SyncSection) => void;
  /** Sync changed something in the vault or the account. */
  onChanged?: () => void;
  /** A command runs: Settings must not close on Escape. */
  onBusy: (busy: boolean) => void;
  /** The Emergency Kit or the joining result is shown: Settings must not close on Escape. */
  onHold: (held: boolean) => void;
  /** How many things wait for the user, for the Settings category. */
  onAttention?: (count: number) => void;
}

/** Settings → Sync: turning sync on or joining, and everything about a synced account. */
export function SyncSettings({ section, onSection, onChanged, onBusy, onHold, onAttention }: Props) {
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
  useEffect(() => onHold(kit !== null || joined !== null), [kit, joined, onHold]);
  useEffect(() => () => onHold(false), [onHold]);
  const attention = attentionCount(screen);
  useEffect(() => onAttention?.(attention), [attention, onAttention]);

  const changed = () => {
    void load();
    onChanged?.();
  };

  let body: ReactNode;
  if (kit) {
    body = (
      <div className="sync-body scroll">
        <div className="sync-single">
          <EmergencyKit
            kit={kit}
            onDone={() => {
              setKit(null);
              changed();
            }}
          />
        </div>
      </div>
    );
  } else if (joined) {
    body = (
      <div className="sync-body scroll">
        <div className="sync-single">
          <JoinResult
            outcome={joined}
            onDone={() => {
              setJoined(null);
              changed();
            }}
          />
        </div>
      </div>
    );
  } else if (screen === null) {
    body = !error && (
      <p className="muted" role="status">
        Loading…
      </p>
    );
  } else if (screen.enabled) {
    return (
      <SyncOn
        screen={screen}
        error={error}
        section={section}
        onSection={onSection}
        onKit={setKit}
        onChanged={changed}
        onBusy={onBusy}
      />
    );
  } else {
    body = <SyncOff onKit={setKit} onJoined={setJoined} onBusy={onBusy} />;
  }
  return (
    <>
      <header className="pane-header">
        <h3 className="pane-title">Sync</h3>
      </header>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      {body}
    </>
  );
}

/** Turning sync on or joining: where the account lives on the left, what to do on the right. */
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
    // JoinSync draws the folder and the form: one per column.
    return (
      <div className="sync-body">
        <p className="muted">Join a synced account: this Mac gets everything the account holds.</p>
        <div className="sync-columns">
          <JoinSync onJoined={onJoined} onCancel={() => setJoining(false)} onBusy={onBusy} />
        </div>
      </div>
    );
  }
  return (
    <div className="sync-body">
      <p className="muted">
        Keep this vault in step across your Macs through iCloud Drive or a folder you choose. Everything is encrypted
        before it leaves this Mac.
      </p>
      <div className="sync-columns">
        <div className="sync-col">
          <SyncPlaceChooser onPlace={setPlace} />
        </div>
        <div className="sync-col">
          <form className="panel" onSubmit={enable} aria-label="Turn on sync">
            <h3>Turn on sync</h3>
            <p className="hint">
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
              <button type="submit" className="primary" disabled={!password || busy || !place} aria-busy={busy}>
                Turn on sync
              </button>
            </div>
          </form>
          <section className="panel" aria-label="Join">
            <h3>Already syncing on another Mac?</h3>
            <p className="hint">Join its account with your master password and its setup code.</p>
            <div className="modal-actions">
              <button className="secondary" onClick={() => setJoining(true)}>
                Join a synced account
              </button>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}

function SyncOn({
  screen,
  error: loadError,
  section,
  onSection,
  onKit,
  onChanged,
  onBusy,
}: {
  screen: SyncScreen;
  error: string | null;
  section: SyncSection;
  onSection: (section: SyncSection) => void;
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
  const ids = useId();
  const tabs = useTabs(SECTION_IDS, section, onSection, "horizontal");
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
  const approvals = status?.mainDevice ? waiting : [];
  const counts: Record<SyncSection, number> = {
    overview: approvals.length + screen.alarms.length,
    devices: approvals.length,
    safety: 0,
    advanced: 0,
  };

  const failed = Boolean(screen.error) || screen.lastRoundOk === false;
  const overview = (
    <div className="sync-columns">
      <div className="sync-col">
        <section className="panel" aria-label="Sync status">
          <div className="status-line">
            <span className={`status-icon ${failed ? "bad" : screen.lastRoundAt ? "good" : ""}`} aria-hidden="true">
              {failed ? <IconAlert /> : screen.lastRoundAt ? <IconCheck /> : <IconSync />}
            </span>
            <div className="status-text">
              <p className="sync-state">
                {screen.error
                  ? "Sync stopped"
                  : screen.lastRoundAt
                    ? screen.lastRoundOk
                      ? "Up to date"
                      : "Sync failed"
                    : "Not synced yet"}
              </p>
              <p className="hint">
                {screen.lastRoundAt ? `Last synced ${formatTime(screen.lastRoundAt)}` : "Nothing synced in this session"}
              </p>
            </div>
          </div>
          {screen.error && (
            <p className="error" role="alert">
              {screen.error}
            </p>
          )}
          {screen.location && (
            <div className="field-line">
              <span className="field-label">Sync folder</span>
              <PathText path={screen.location} label="sync folder path" />
            </div>
          )}
          {status?.waitingForApproval && (
            <p className="callout">
              This Mac waits for your main Mac to approve it. The main Mac must see this code:{" "}
              <span className="mono">{status.keyCode}</span>
            </p>
          )}
          {status && !status.mainDevice && !status.rootConfirmed && (
            <p className="hint">Changes from other devices aren't confirmed by your main Mac yet.</p>
          )}
          <div className="modal-actions start">
            <button className="secondary" disabled={busy} onClick={() => run(api.syncNow)}>
              Sync now
            </button>
          </div>
        </section>
        {screen.notices.length > 0 && (
          <section className="panel" aria-label="Notices">
            <h3>Notices</h3>
            <ul className="plain">
              {screen.notices.map((n, i) => (
                <li key={i} className="hint">
                  {n}
                </li>
              ))}
            </ul>
          </section>
        )}
      </div>
      <div className="sync-col">
        <section className="panel grow" aria-label="Attention">
          <div className="panel-head">
            <h3>Needs your attention</h3>
            {counts.overview > 0 && <span className="badge">{counts.overview}</span>}
          </div>
          {counts.overview === 0 ? (
            <div className="calm">
              <IconShieldCheck width={28} height={28} />
              <strong>All clear</strong>
              <p className="hint">Devices waiting for approval and anything that looks wrong show up here.</p>
            </div>
          ) : (
            <div className="panel-scroll">
              {approvals.length > 0 && (
                <section aria-label="Approvals">
                  <ul className="rows">
                    {approvals.map((d) => (
                      <li key={d.id} className="row-item">
                        <span className="tile" aria-hidden="true">
                          <IconLaptop />
                        </span>
                        <span className="row-text">
                          <strong>{d.name}</strong>
                          <span className="hint">Asked to join your account</span>
                        </span>
                        <button className="primary" disabled={busy} onClick={() => setApproving(d)}>
                          Review
                        </button>
                      </li>
                    ))}
                  </ul>
                </section>
              )}
              {screen.alarms.length > 0 && (
                <section aria-label="Alarms">
                  <ul className="rows">
                    {screen.alarms.map((a) => (
                      <li key={a.id} className="alarm">
                        <span className="tile warn" aria-hidden="true">
                          <IconAlert />
                        </span>
                        <div className="row-text">
                          <strong>{a.title}</strong>
                          <p className="hint">{a.explanation}</p>
                          {a.actions.length > 0 && (
                            <div className="modal-actions start">
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
                          )}
                        </div>
                      </li>
                    ))}
                  </ul>
                </section>
              )}
            </div>
          )}
        </section>
      </div>
    </div>
  );

  const current = status?.devices.filter((d) => !d.removed) ?? [];
  // Waiting devices first: they are the ones to act on.
  current.sort((a, b) => Number(a.approved) - Number(b.approved));
  const removed = status?.devices.filter((d) => d.removed) ?? [];
  const deviceRow = (d: SyncDevice) => {
    const tags = [
      d.main && "Main Mac",
      d.thisDevice && "This Mac",
      !d.main && d.approved && !d.removed && "Approved",
      !d.approved && "Waiting",
      d.removed && "Removed",
    ].filter((t): t is string => Boolean(t));
    return (
      <li key={d.id} className={d.removed ? "row-item muted-row" : "row-item"}>
        <span className="tile" aria-hidden="true">
          <IconLaptop />
        </span>
        <span className="row-text">
          <strong>{d.name}</strong>
          <span className="tags">
            {tags.map((t) => (
              <span key={t} className={t === "Waiting" ? "tag warn" : "tag"}>
                {t}
              </span>
            ))}
          </span>
        </span>
        {status?.mainDevice && !d.approved && !d.removed && (
          <button className="primary" disabled={busy} onClick={() => setApproving(d)}>
            Review
          </button>
        )}
        {status?.mainDevice && !d.thisDevice && d.approved && !d.removed && (
          <button className="secondary" disabled={busy} onClick={() => setRemoving(d)}>
            Remove
          </button>
        )}
      </li>
    );
  };
  const devices = status ? (
    <div className="sync-stack">
      <p className="muted">
        {status.mainDevice
          ? "This is your main Mac: it approves the Macs that join and can remove them. Review a Mac only if you just set it up yourself."
          : "Your main Mac approves the Macs that join and can remove them."}
      </p>
      <section className="panel grow" aria-label="Devices">
        <div className="panel-head">
          <h3>Devices in this account</h3>
          <span className="hint">{plural(current.length, "device")}</span>
        </div>
        <div className="panel-scroll">
          <ul className="rows">{current.map(deviceRow)}</ul>
          {removed.length > 0 && (
            <details className="removed">
              <summary>Removed ({removed.length})</summary>
              <ul className="rows">{removed.map(deviceRow)}</ul>
            </details>
          )}
        </div>
      </section>
    </div>
  ) : (
    <p className="muted">No devices yet.</p>
  );

  const problems = report
    ? report.damaged + report.damagedAttachments + report.differing.length + report.missing
    : 0;
  const safety = (
    <div className="sync-columns wide-left">
      <div className="sync-col">
        <div className="tool">
          <span className="tile" aria-hidden="true">
            <IconLifebuoy />
          </span>
          <div className="row-text">
            <h3>Emergency Kit</h3>
            <span className="hint">Print or view your recovery details.</span>
          </div>
          <button className="secondary" disabled={busy} onClick={() => openKit(null)}>
            Open kit
          </button>
          {kitPassword !== null && (
            <form
              className="tool-result row"
              onSubmit={(e) => {
                e.preventDefault();
                void openKit(kitPassword);
              }}
            >
              <label>
                Master password for the Emergency Kit
                <input
                  type="password"
                  autoFocus
                  value={kitPassword}
                  onChange={(e) => setKitPassword(e.target.value)}
                />
              </label>
              <button type="button" onClick={() => setKitPassword(null)}>
                Cancel
              </button>
              <button type="submit" className="primary" disabled={!kitPassword || busy}>
                Show
              </button>
            </form>
          )}
        </div>
        <div className="tool">
          <span className="tile" aria-hidden="true">
            <IconShieldCheck />
          </span>
          <div className="row-text">
            <h3>Verify everything</h3>
            <span className="hint">Check every item and attachment.</span>
          </div>
          <button
            className="secondary"
            disabled={busy}
            onClick={() => run(async () => setReport(await api.verifySync()))}
          >
            Verify
          </button>
          {report && (
            <p role="status" aria-label="Verify" className={problems === 0 ? "tool-result ok" : "tool-result bad"}>
              {plural(report.items, "item")} and {plural(report.attachments, "attachment")} checked.{" "}
              {problems === 0
                ? "Everything matches."
                : [
                    report.damaged && `${report.damaged} unreadable`,
                    report.damagedAttachments && plural(report.damagedAttachments, "unreadable attachment"),
                    report.differing.length && `differs from sync: ${report.differing.join(", ")}`,
                    report.missing && `${report.missing} not here yet`,
                  ]
                    .filter(Boolean)
                    .join("; ")}
            </p>
          )}
        </div>
        <div className="tool">
          <span className="tile" aria-hidden="true">
            <IconFolder />
          </span>
          <div className="row-text">
            <h3>What the folder sees</h3>
            <span className="hint">List the encrypted files in the sync folder.</span>
          </div>
          <button
            className="secondary"
            disabled={busy}
            onClick={() => run(async () => setFiles(await api.syncFolderFiles()))}
          >
            List files
          </button>
          {files && (
            <div className="tool-result table-scroll">
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
            </div>
          )}
        </div>
      </div>
      <div className="sync-col">
        <section className="panel grow" aria-label="Backups">
          <div className="panel-head">
            <h3>Copies of your vault on this Mac</h3>
          </div>
          <p className="hint">Kept when the vault was upgraded or replaced by joining an account. You can delete them.</p>
          {backups.length > 0 ? (
            <ul className="rows panel-scroll">
              {backups.map((b) => (
                <li key={b.name} className="row-item">
                  <span className="tile" aria-hidden="true">
                    <IconArchive />
                  </span>
                  <span className="row-text">
                    <strong title={formatTime(b.modified)}>{formatDate(b.modified)}</strong>
                    <span className="hint">
                      {b.kind === "migration" ? "Before an upgrade" : "Before joining an account"} · {formatSize(b.size)}
                    </span>
                  </span>
                  <button className="secondary" disabled={busy} onClick={() => setDeleting(b)}>
                    Delete
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <p className="calm-line">None yet.</p>
          )}
        </section>
      </div>
    </div>
  );

  const groups = groupLog(screen.log);
  const advanced = (
    <div className="sync-stack">
      <section className="panel grow" aria-label="Log">
        <div className="panel-head">
          <h3>Sync log</h3>
          <span className="hint">This session, newest first</span>
        </div>
        {groups.length === 0 ? (
          <p className="calm-line">Nothing yet in this session.</p>
        ) : (
          <div className="table-scroll grow">
            <table className="log-table" aria-label="Sync log">
              <thead>
                <tr>
                  <th scope="col">Time</th>
                  <th scope="col">Event</th>
                </tr>
              </thead>
              <tbody>
                {groups.map((g, i) => (
                  <tr key={`${g.at}-${i}`}>
                    <td
                      className="time"
                      title={g.count > 1 ? `${formatTime(g.firstAt)} – ${formatTime(g.at)}` : formatTime(g.at)}
                    >
                      {formatLogTime(g.at)}
                    </td>
                    <td>
                      {g.text}
                      {g.count > 1 && (
                        <span className="repeat" aria-label={`${g.count} times`}>
                          ×{g.count}
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      <section className="panel danger-zone" aria-label="Danger zone">
        <h3>Danger zone</h3>
        <div className="danger-row">
          <div className="row-text">
            <strong>Turn off sync</strong>
            <span className="hint">This Mac stops syncing. Everything stays in this vault; you can join again later.</span>
          </div>
          <button className="secondary" onClick={() => setTurningOff(true)}>
            Turn off sync
          </button>
        </div>
        {status?.mainDevice && (
          <div className="danger-row">
            <div className="row-text">
              <strong>Start a new account</strong>
              <span className="hint">
                New keys for everything, for a stolen or copied device. Your other Macs join again.
              </span>
            </div>
            <button className="danger" onClick={() => setStartingOver(true)}>
              Start a new account
            </button>
          </div>
        )}
      </section>
    </div>
  );

  const panes: Record<SyncSection, ReactNode> = { overview, devices, safety, advanced };
  return (
    <>
      <header className="pane-header">
        <h3 className="pane-title">Sync</h3>
        <div
          className="subtabs"
          role="tablist"
          aria-label="Sync sections"
          aria-orientation="horizontal"
          onKeyDown={tabs.onKeyDown}
        >
          {SECTIONS.map((s) => (
            <button
              key={s.id}
              id={`${ids}-tab-${s.id}`}
              {...tabs.tab(s.id, `${ids}-pane`)}
              aria-label={tabName(s.label, counts[s.id])}
            >
              {s.label}
              {counts[s.id] > 0 && (
                <span className="badge" aria-hidden="true">
                  {counts[s.id]}
                </span>
              )}
            </button>
          ))}
        </div>
      </header>
      <div
        className="sync-pane"
        role="tabpanel"
        id={`${ids}-pane`}
        aria-labelledby={`${ids}-tab-${section}`}
        key={section}
      >
        {(error ?? loadError) && (
          <p className="error" role="alert">
            {error ?? loadError}
          </p>
        )}
        {panes[section]}
      </div>

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
          Its changes stop counting on your other devices. It still holds the account key, so it can read new
          changes for as long as it can reach the sync folder. If it was lost or stolen, also remove its access to the
          folder (iCloud: sign it out of your Apple ID) and start a new account (Sync → Advanced).
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
          <button type="submit" className="danger" disabled={!password || busy} aria-busy={busy}>
            Start a new account
          </button>
        </div>
      </form>
    </div>
  );
}
