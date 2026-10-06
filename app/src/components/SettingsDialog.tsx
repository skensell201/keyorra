import { useCallback, useEffect, useId, useRef, useState, type FormEvent, type ReactNode } from "react";
import { IconClose, IconGlobe, IconLock, IconSliders, IconSync } from "./icons";
import { api, errorMessage, isCmdError, type PairedBrowser, type Settings, type TouchIdState } from "../api";
import { applyTheme, loadTheme, THEMES, type Theme } from "../theme";
import { SyncSettings, type SyncSection } from "./SyncSettings";
import { tabName, useTabs } from "./tabs";

const LOCK_MINUTES = [1, 5, 10, 30, 60, 240];
const CLIPBOARD_SECONDS = [30, 60, 90, 180];
const MIN_LENGTH = 10;

function withCurrent(options: number[], value: number) {
  return options.includes(value) ? options : [...options, value].sort((a, b) => a - b);
}

export type SettingsCategory = "general" | "security" | "sync" | "browsers";
const CATEGORIES: { id: SettingsCategory; label: string; icon: ReactNode }[] = [
  { id: "general", label: "General", icon: <IconSliders /> },
  { id: "security", label: "Security", icon: <IconLock /> },
  { id: "sync", label: "Sync", icon: <IconSync /> },
  { id: "browsers", label: "Browsers", icon: <IconGlobe /> },
];
const CATEGORY_IDS = CATEGORIES.map((c) => c.id);

/** Where Settings opens: a category, and for Sync one of its sections. */
export interface SettingsPlace {
  category: SettingsCategory;
  sync?: SyncSection;
}

interface Props {
  onClose: () => void;
  /** Sync changed the vault or the account. */
  onSyncChanged?: () => void;
  initial?: SettingsPlace;
}

/**
 * Settings: one wide window, categories on the left and one pane on the right. Nothing in it
 * scrolls as a whole; a long list scrolls inside its own panel. Choices save as they are made;
 * only the master password has its own button.
 */
export function SettingsDialog({ onClose, onSyncChanged, initial }: Props) {
  const [category, setCategory] = useState<SettingsCategory>(initial?.category ?? "general");
  const [syncSection, setSyncSection] = useState<SyncSection>(initial?.sync ?? "overview");
  const [syncAttention, setSyncAttention] = useState(0);
  const ids = useId();
  const nav = useTabs(CATEGORY_IDS, category, setCategory, "vertical");
  const dialog = useRef<HTMLDivElement>(null);

  // Escape closes Settings only when nothing is under way (review A3 I7): not while a command
  // runs, the Emergency Kit or a joining result is shown, or a dialog inside is open.
  const [passwordBusy, setPasswordBusy] = useState(false);
  const syncBusy = useRef(false);
  const syncHeld = useRef(false);
  const onSyncBusy = useCallback((b: boolean) => {
    syncBusy.current = b;
  }, []);
  const onSyncHold = useCallback((h: boolean) => {
    syncHeld.current = h;
  }, []);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape" || passwordBusy || syncBusy.current || syncHeld.current) return;
      if (dialog.current?.querySelector('[aria-modal="true"]')) return;
      onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose, passwordBusy]);

  const counts: Record<SettingsCategory, number> = { general: 0, security: 0, sync: syncAttention, browsers: 0 };
  const panel = (id: SettingsCategory) => ({
    id: `${ids}-panel-${id}`,
    role: "tabpanel" as const,
    "aria-labelledby": `${ids}-tab-${id}`,
    hidden: category !== id,
    className: "settings-pane",
  });

  return (
    <div className="modal-backdrop">
      <div
        className="card modal settings"
        role="dialog"
        aria-modal="true"
        aria-labelledby="settings-title"
        ref={dialog}
      >
        <header className="modal-header">
          <h2 id="settings-title">Settings</h2>
          <button className="icon" aria-label="Close" onClick={onClose} disabled={passwordBusy}>
            <IconClose />
          </button>
        </header>
        <div className="settings-layout">
          <div
            className="settings-nav"
            role="tablist"
            aria-label="Settings sections"
            aria-orientation="vertical"
            onKeyDown={nav.onKeyDown}
          >
            {CATEGORIES.map((c) => (
              <button
                key={c.id}
                id={`${ids}-tab-${c.id}`}
                {...nav.tab(c.id, `${ids}-panel-${c.id}`)}
                aria-label={tabName(c.label, counts[c.id])}
              >
                {c.icon}
                {c.label}
                {counts[c.id] > 0 && (
                  <span className="badge" aria-hidden="true">
                    {counts[c.id]}
                  </span>
                )}
              </button>
            ))}
          </div>
          {/* Every pane stays mounted, so what was typed or shown survives switching. */}
          <div {...panel("general")}>
            <General />
          </div>
          <div {...panel("security")}>
            <Security onBusy={setPasswordBusy} />
          </div>
          <div {...panel("sync")}>
            <SyncSettings
              section={syncSection}
              onSection={setSyncSection}
              onChanged={onSyncChanged}
              onBusy={onSyncBusy}
              onHold={onSyncHold}
              onAttention={setSyncAttention}
            />
          </div>
          <div {...panel("browsers")}>
            <Browsers />
          </div>
        </div>
      </div>
    </div>
  );
}

function PaneHeader({ title }: { title: string }) {
  return (
    <header className="pane-header">
      <h3 className="pane-title">{title}</h3>
    </header>
  );
}

/** Timeouts and appearance; each choice is saved at once. */
function General() {
  const [theme, setTheme] = useState<Theme>(loadTheme);
  const [settings, setSettings] = useState<Settings | null>(null);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Only the reply to the latest change counts.
  const saving = useRef(0);

  useEffect(() => {
    api
      .settings()
      .then(setSettings)
      .catch((e) => setError(`Couldn't load settings: ${errorMessage(e)}`));
  }, []);

  async function save(next: Settings) {
    const seq = ++saving.current;
    setSettings(next);
    setSaved(false);
    setError(null);
    try {
      const stored = await api.updateSettings(next);
      if (seq !== saving.current) return;
      setSettings(stored);
      setSaved(true);
    } catch (e) {
      if (seq === saving.current) setError(`Couldn't save settings: ${errorMessage(e)}`);
    }
  }

  return (
    <>
      <PaneHeader title="General" />
      <section className="panel" aria-label="Locking">
        <div className="panel-head">
          <h3>Locking and clipboard</h3>
          <span className="status" role="status" aria-label="Settings saved">
            {saved ? "Saved" : ""}
          </span>
        </div>
        {settings && (
          <div className="modal-grid">
            <label>
              Lock after
              <select
                value={String(settings.autoLockMinutes)}
                onChange={(e) => void save({ ...settings, autoLockMinutes: Number(e.target.value) })}
              >
                {withCurrent(LOCK_MINUTES, settings.autoLockMinutes).map((m) => (
                  <option key={m} value={m}>
                    {m} min of inactivity
                  </option>
                ))}
              </select>
            </label>
            <label>
              Clear copied secrets after
              <select
                value={String(settings.clipboardSeconds)}
                onChange={(e) => void save({ ...settings, clipboardSeconds: Number(e.target.value) })}
              >
                {withCurrent(CLIPBOARD_SECONDS, settings.clipboardSeconds).map((s) => (
                  <option key={s} value={s}>
                    {s} seconds
                  </option>
                ))}
              </select>
            </label>
          </div>
        )}
        <p className="hint">Changes are saved as you make them.</p>
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
      </section>
      <section className="panel" aria-label="Appearance">
        <h3>Appearance</h3>
        <div className="segmented" role="group" aria-label="Theme">
          {THEMES.map((t) => (
            <button
              key={t.id}
              type="button"
              aria-pressed={theme === t.id}
              onClick={() => {
                applyTheme(t.id);
                setTheme(t.id);
              }}
            >
              {t.label}
            </button>
          ))}
        </div>
      </section>
    </>
  );
}

/** Touch ID and the master password. */
function Security({ onBusy }: { onBusy: (busy: boolean) => void }) {
  const [touchId, setTouchId] = useState<TouchIdState | null>(null);
  const [touchIdError, setTouchIdError] = useState<string | null>(null);
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [changed, setChanged] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => onBusy(busy), [busy, onBusy]);

  useEffect(() => {
    api
      .touchIdState()
      .then(setTouchId)
      .catch(() => setTouchId(null));
  }, []);
  async function toggleTouchId(on: boolean) {
    setTouchIdError(null);
    try {
      if (on) await api.enableTouchId();
      else await api.disableTouchId();
      setTouchId(await api.touchIdState());
    } catch (e) {
      setTouchIdError(errorMessage(e));
    }
  }

  const canChange = current.length > 0 && next.length >= MIN_LENGTH && next === confirm && !busy;
  async function change(e: FormEvent) {
    e.preventDefault();
    if (!canChange) return;
    setBusy(true);
    setError(null);
    setChanged(false);
    try {
      await api.changePassword(current, next);
      setChanged(true);
      setCurrent("");
      setNext("");
      setConfirm("");
    } catch (err) {
      setError(isCmdError(err) && err.kind === "wrongPassword" ? "Current password is incorrect" : errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <PaneHeader title="Security" />
      <div className="pane-columns">
        <section className="panel" aria-label="Touch ID">
          <h3>Touch ID</h3>
          {touchId && !touchId.available && <p className="hint">Touch ID isn't available on this Mac.</p>}
          {touchId?.available && (
            <label className="check">
              <input type="checkbox" checked={touchId.enabled} onChange={(e) => toggleTouchId(e.target.checked)} />
              Unlock with Touch ID
            </label>
          )}
          <p className="hint">
            Keyorra still asks for your master password every 14 days and after your fingerprints change.
          </p>
          {touchIdError && (
            <p className="error" role="alert">
              {touchIdError}
            </p>
          )}
        </section>
        <form className="panel" onSubmit={change} aria-label="Change master password">
          <h3>Change master password</h3>
          <label>
            Current password
            <input type="password" value={current} onChange={(e) => setCurrent(e.target.value)} />
          </label>
          <label>
            New password
            <input type="password" value={next} onChange={(e) => setNext(e.target.value)} />
          </label>
          <label>
            Confirm new password
            <input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
          </label>
          {next.length > 0 && next.length < MIN_LENGTH && <p className="error">Use at least {MIN_LENGTH} characters</p>}
          {error && (
            <p className="error" role="alert">
              {error}
            </p>
          )}
          <div className="modal-actions">
            <span className="status" role="status" aria-label="Password change">
              {changed ? "Password changed" : ""}
            </span>
            <button type="submit" className="primary" disabled={!canChange} aria-busy={busy}>
              Change password
            </button>
          </div>
        </form>
      </div>
    </>
  );
}

/** Browsers paired with the extension, and connecting new ones. */
function Browsers() {
  const [browsers, setBrowsers] = useState<PairedBrowser[]>([]);
  const [failed, setFailed] = useState(false);
  const [note, setNote] = useState("");
  useEffect(() => {
    api
      .pairedBrowsers()
      .then(setBrowsers)
      .catch(() => setFailed(true));
  }, []);
  async function connect() {
    try {
      const found = await api.connectBrowsers();
      // Entries like "Safari: install Keyorra for Safari" are advice, not ready browsers.
      const ready = found.filter((b) => !b.includes(":"));
      const advice = found.filter((b) => b.includes(":")).map((a) => ` ${a}.`);
      setNote(
        (ready.length
          ? `Ready in ${ready.join(", ")}. Load the Keyorra extension there and click Connect.`
          : "No supported browsers found.") + advice.join(""),
      );
    } catch (e) {
      setNote(errorMessage(e));
    }
  }
  async function disconnect(b: PairedBrowser) {
    try {
      await api.removePairedBrowser(b.clientId);
      setBrowsers((all) => all.filter((x) => x.clientId !== b.clientId));
    } catch (e) {
      setNote(errorMessage(e));
    }
  }

  return (
    <>
      <PaneHeader title="Browsers" />
      <p className="muted">
        The Keyorra extension fills logins in your browsers. Each browser asks once to connect, and you confirm it here
        in the app.
      </p>
      <section className="panel grow" aria-label="Connected browsers">
        <h3>Connected browsers</h3>
        {browsers.length > 0 ? (
          <ul className="rows panel-scroll">
            {browsers.map((b) => (
              <li key={b.clientId} className="row-item">
                <span className="tile" aria-hidden="true">
                  <IconGlobe />
                </span>
                <span className="row-text">
                  <strong>{b.name}</strong>
                </span>
                <button className="icon" aria-label={`Disconnect ${b.name}`} title="Disconnect" onClick={() => disconnect(b)}>
                  <IconClose />
                </button>
              </li>
            ))}
          </ul>
        ) : failed ? (
          <p className="calm-line">Couldn't load browsers</p>
        ) : (
          <p className="calm-line">No browsers connected yet.</p>
        )}
        <div className="modal-actions">
          <span className="note" role="status" aria-label="Browsers">
            {note}
          </span>
          <button className="secondary" onClick={connect}>
            Connect browsers
          </button>
        </div>
      </section>
    </>
  );
}
