import { useEffect, useState, type FormEvent } from "react";
import { IconClose } from "./icons";
import { api, errorMessage, isCmdError, type PairedBrowser, type Settings, type TouchIdState } from "../api";
import { applyTheme, loadTheme, THEMES, type Theme } from "../theme";

const LOCK_MINUTES = [1, 5, 10, 30, 60, 240];
const CLIPBOARD_SECONDS = [30, 60, 90, 180];
const MIN_LENGTH = 10;

function withCurrent(options: number[], value: number) {
  return options.includes(value) ? options : [...options, value].sort((a, b) => a - b);
}

export function SettingsDialog({ onClose }: { onClose: () => void }) {
  const [theme, setTheme] = useState<Theme>(loadTheme);
  const [settings, setSettings] = useState<Settings | null>(null);
  const [saved, setSaved] = useState(false);
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [changed, setChanged] = useState(false);
  const [settingsError, setSettingsError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [browsers, setBrowsers] = useState<PairedBrowser[]>([]);
  const [browsersFailed, setBrowsersFailed] = useState(false);
  const [browsersNote, setBrowsersNote] = useState("");
  const [touchId, setTouchId] = useState<TouchIdState | null>(null);
  const [touchIdError, setTouchIdError] = useState<string | null>(null);
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
  useEffect(() => {
    api
      .pairedBrowsers()
      .then(setBrowsers)
      .catch(() => setBrowsersFailed(true));
  }, []);
  async function connectBrowsers() {
    try {
      const found = await api.connectBrowsers();
      // Entries like "Safari: install Keyorra for Safari" are advice, not ready browsers.
      const ready = found.filter((b) => !b.includes(":"));
      const advice = found.filter((b) => b.includes(":")).map((a) => ` ${a}.`);
      setBrowsersNote(
        (ready.length
          ? `Ready in ${ready.join(", ")}. Load the Keyorra extension there and click Connect.`
          : "No supported browsers found.") + advice.join(""),
      );
    } catch (e) {
      setBrowsersNote(errorMessage(e));
    }
  }
  async function disconnect(b: PairedBrowser) {
    try {
      await api.removePairedBrowser(b.clientId);
      setBrowsers((all) => all.filter((x) => x.clientId !== b.clientId));
    } catch (e) {
      setBrowsersNote(errorMessage(e));
    }
  }

  useEffect(() => {
    api
      .settings()
      .then(setSettings)
      .catch((e) => setSettingsError(`Couldn't load settings: ${errorMessage(e)}`));
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && !busy && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose, busy]);

  async function save() {
    if (!settings) return;
    setSettingsError(null);
    try {
      setSettings(await api.updateSettings(settings));
      setSaved(true);
    } catch (e) {
      setSettingsError(`Couldn't save settings: ${errorMessage(e)}`);
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
    <div className="modal-backdrop">
      <div className="card modal" role="dialog" aria-modal="true" aria-labelledby="settings-title">
        <header className="modal-header">
          <h2 id="settings-title">Settings</h2>
          <button className="icon" aria-label="Close" onClick={onClose} disabled={busy}>
            <IconClose />
          </button>
        </header>

        <section className="modal-section">
          <h3>Security</h3>
          {settings && (
            <>
              <div className="modal-grid">
                <label>
                  Lock after
                  <select
                    value={String(settings.autoLockMinutes)}
                    onChange={(e) => {
                      setSaved(false);
                      setSettings({ ...settings, autoLockMinutes: Number(e.target.value) });
                    }}
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
                    onChange={(e) => {
                      setSaved(false);
                      setSettings({ ...settings, clipboardSeconds: Number(e.target.value) });
                    }}
                  >
                    {withCurrent(CLIPBOARD_SECONDS, settings.clipboardSeconds).map((s) => (
                      <option key={s} value={s}>
                        {s} seconds
                      </option>
                    ))}
                  </select>
                </label>
              </div>
              <div className="modal-actions">
                <span className="status" role="status" aria-label="Settings saved">
                  {saved ? "Saved" : ""}
                </span>
                <button className="primary" onClick={save}>
                  Save settings
                </button>
              </div>
            </>
          )}
          {settingsError && (
            <p className="error" role="alert">
              {settingsError}
            </p>
          )}
        </section>

        <section className="modal-section">
          <h3>Touch ID</h3>
          {touchId && !touchId.available && <p className="muted">Touch ID isn't available on this Mac.</p>}
          {touchId?.available && (
            <label className="check">
              <input type="checkbox" checked={touchId.enabled} onChange={(e) => toggleTouchId(e.target.checked)} />
              Unlock with Touch ID
            </label>
          )}
          <p className="muted">
            Keyorra still asks for your master password every 14 days and after your fingerprints change.
          </p>
          {touchIdError && (
            <p className="error" role="alert">
              {touchIdError}
            </p>
          )}
        </section>

        <form className="modal-section" onSubmit={change}>
          <h3>Change master password</h3>
          <label>
            Current password
            <input type="password" value={current} onChange={(e) => setCurrent(e.target.value)} />
          </label>
          <div className="modal-grid">
            <label>
              New password
              <input type="password" value={next} onChange={(e) => setNext(e.target.value)} />
            </label>
            <label>
              Confirm new password
              <input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
            </label>
          </div>
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
            <button type="submit" className="secondary" disabled={!canChange}>
              Change password
            </button>
          </div>
        </form>

        <section className="modal-section">
          <h3>Browsers</h3>
          {browsers.length > 0 ? (
            <ul className="browser-list">
              {browsers.map((b) => (
                <li key={b.clientId}>
                  <span>{b.name}</span>
                  <button className="icon" aria-label={`Disconnect ${b.name}`} title="Disconnect" onClick={() => disconnect(b)}>
                    <IconClose />
                  </button>
                </li>
              ))}
            </ul>
          ) : browsersFailed ? (
            <p className="muted">Couldn't load browsers</p>
          ) : (
            <p className="muted">No browsers connected yet.</p>
          )}
          <div className="modal-actions">
            <span className="status" role="status" aria-label="Browsers">
              {browsersNote}
            </span>
            <button className="secondary" onClick={connectBrowsers}>
              Connect browsers
            </button>
          </div>
        </section>

        <section className="modal-section">
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
      </div>
    </div>
  );
}
