import { Keyhole } from "./Keyhole";
import { useEffect, useState, type FormEvent } from "react";
import { api, errorMessage, isCmdError } from "../api";

interface Props {
  onUnlocked: () => void;
  /** The database was moved aside: show first-run setup. */
  onStartOver: () => void;
}

export function Unlock({ onUnlocked, onStartOver }: Props) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [wait, setWait] = useState(0);
  const [busy, setBusy] = useState(false);
  const [shakes, setShakes] = useState(0);
  const [unreadable, setUnreadable] = useState(false);
  const [confirmStartOver, setConfirmStartOver] = useState(false);

  useEffect(() => {
    if (wait <= 0) return;
    const timer = setTimeout(() => {
      setWait((w) => w - 1);
      if (wait === 1) setError(null);
    }, 1000);
    return () => clearTimeout(timer);
  }, [wait]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!password || wait > 0) return;
    setBusy(true);
    setError(null);
    try {
      await api.unlock(password);
      onUnlocked();
    } catch (err) {
      setPassword("");
      if (isCmdError(err) && err.kind === "throttled") {
        setWait(err.retryAfter ?? 1);
        setError(err.message);
      } else if (isCmdError(err) && err.kind === "notADatabase") {
        setUnreadable(true);
      } else if (isCmdError(err) && err.kind === "wrongPassword") {
        setError("Incorrect password");
        setShakes((n) => n + 1);
      } else {
        setError(errorMessage(err));
      }
    } finally {
      setBusy(false);
    }
  }

  async function startOver() {
    setBusy(true);
    try {
      await api.startOver();
      onStartOver();
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  }

  if (unreadable) {
    return (
      <div className="center">
        <div className="card auth" role="group" aria-labelledby="unreadable-title">
          <h1 id="unreadable-title">This file is not a Keepsake database</h1>
          <p className="muted">
            Keepsake can't read its database: it belongs to another app or is damaged. You can start over with a new,
            empty vault. The old file is moved aside next to it (it ends in ".unreadable-…"), never deleted.
          </p>
          {error && (
            <p className="error" role="alert">
              {error}
            </p>
          )}
          {confirmStartOver ? (
            <button className="danger" onClick={startOver} disabled={busy}>
              Move it aside and start over
            </button>
          ) : (
            <button className="primary" onClick={() => setConfirmStartOver(true)}>
              Start over…
            </button>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="center">
      <form key={shakes} className={shakes ? "card auth shake" : "card auth"} onSubmit={submit}>
        <div className="logo">
          <Keyhole width={24} height={24} />
        </div>
        <h1>Keepsake is locked</h1>
        <label>
          Master password
          <input type="password" autoFocus value={password} onChange={(e) => setPassword(e.target.value)} />
        </label>
        {error && (
          <p className="error" role="alert">
            {wait > 0 ? `Too many attempts. Try again in ${wait} s.` : error}
          </p>
        )}
        <button className="primary" type="submit" disabled={busy || !password || wait > 0}>
          {busy ? "Unlocking…" : "Unlock"}
        </button>
      </form>
    </div>
  );
}
