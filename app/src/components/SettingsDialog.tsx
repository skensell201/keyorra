import { useEffect, useState, type FormEvent } from "react";
import { api, errorMessage, isCmdError, type Settings } from "../api";

const LOCK_MINUTES = [1, 5, 10, 30, 60, 240];
const CLIPBOARD_SECONDS = [30, 60, 90, 180];
const MIN_LENGTH = 10;

export function SettingsDialog({ onClose }: { onClose: () => void }) {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [saved, setSaved] = useState(false);
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [changed, setChanged] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.settings().then(setSettings).catch((e) => setError(errorMessage(e)));
  }, []);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  async function save() {
    if (!settings) return;
    setError(null);
    try {
      setSettings(await api.updateSettings(settings));
      setSaved(true);
    } catch (e) {
      setError(errorMessage(e));
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
        <h2 id="settings-title">Settings</h2>
        {settings && (
          <>
            <label>
              Lock after
              <select
                value={String(settings.autoLockMinutes)}
                onChange={(e) => {
                  setSaved(false);
                  setSettings({ ...settings, autoLockMinutes: Number(e.target.value) });
                }}
              >
                {LOCK_MINUTES.map((m) => (
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
                {CLIPBOARD_SECONDS.map((s) => (
                  <option key={s} value={s}>
                    {s} seconds
                  </option>
                ))}
              </select>
            </label>
            <div className="actions">
              <button className="primary" onClick={save}>
                Save settings
              </button>
              {saved && <span role="status">Saved</span>}
            </div>
          </>
        )}
        <form className="editor" onSubmit={change}>
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
          <div className="actions">
            <button type="submit" disabled={!canChange}>
              Change password
            </button>
            {changed && <span>Password changed</span>}
          </div>
        </form>
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        <button onClick={onClose}>Close</button>
      </div>
    </div>
  );
}
