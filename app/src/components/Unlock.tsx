import { ConfirmDialog } from "./ConfirmDialog";
import { Keyhole } from "./Keyhole";
import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { api, errorMessage, isCmdError, type TouchIdState } from "../api";

interface Props {
  /** The user just locked from this window: don't ask for Touch ID until it comes back to the front. */
  justLocked?: boolean;
  onUnlocked: () => void;
  /** The database was moved aside: show first-run setup. */
  onStartOver: () => void;
}

export function Unlock({ onUnlocked, onStartOver, justLocked = false }: Props) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [wait, setWait] = useState(0);
  const [busy, setBusy] = useState(false);
  const [shakes, setShakes] = useState(0);
  const [touchId, setTouchId] = useState<TouchIdState | null>(null);
  const prompted = useRef(false);
  const canTouch = Boolean(touchId?.available && touchId.enabled && !touchId.passwordDue);

  useEffect(() => {
    api
      .touchIdState()
      .then(setTouchId)
      .catch(() => setTouchId(null));
  }, []);

  const touchUnlock = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      await api.unlockWithTouchId();
      onUnlocked();
    } catch (err) {
      if (isCmdError(err) && err.kind === "cancelled") {
        // The user chose the password instead; nothing to say.
      } else if (isCmdError(err) && err.kind === "passwordRequired") {
        setTouchId(null);
        setError(err.message);
      } else if (isCmdError(err) && err.kind === "notADatabase") {
        setUnreadable(true);
      } else {
        setError(errorMessage(err));
      }
    } finally {
      setBusy(false);
    }
  }, [onUnlocked]);

  // Ask once, as soon as this window is in front (not while the Mac sits idle behind it).
  useEffect(() => {
    if (!canTouch) return;
    const attempt = () => {
      if (prompted.current) return;
      prompted.current = true;
      void touchUnlock();
    };
    if (document.hasFocus() && !justLocked) attempt();
    window.addEventListener("focus", attempt);
    return () => window.removeEventListener("focus", attempt);
  }, [canTouch, touchUnlock, justLocked]);
  const [unreadable, setUnreadable] = useState(false);
  const [confirmStartOver, setConfirmStartOver] = useState(false);
  /** Where the unreadable file went, shown before setup starts. */
  const [movedTo, setMovedTo] = useState<string | null>(null);

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
    setConfirmStartOver(false);
    setBusy(true);
    setError(null);
    try {
      setMovedTo(await api.startOver());
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  if (movedTo !== null) {
    return (
      <div className="center">
        <div className="card auth" role="group" aria-labelledby="moved-title">
          <h1 id="moved-title">The old file was moved aside</h1>
          <p className="muted">It is kept here, untouched:</p>
          <p>
            <code className="path">{movedTo}</code>
          </p>
          <button className="primary" autoFocus onClick={onStartOver}>
            Set up a new vault
          </button>
        </div>
      </div>
    );
  }

  if (unreadable) {
    return (
      <div className="center">
        <div className="card auth" role="group" aria-labelledby="unreadable-title">
          <h1 id="unreadable-title">This file is not a Keyorra database</h1>
          <p className="muted">
            Keyorra can't read its database: it belongs to another app or is damaged. You can start over with a new,
            empty vault. The old file is moved aside next to it (it ends in ".unreadable-…"), never deleted.
          </p>
          {error && (
            <p className="error" role="alert">
              {error}
            </p>
          )}
          <button className="primary" onClick={() => setConfirmStartOver(true)} disabled={busy}>
            {busy ? "Moving…" : "Start over…"}
          </button>
          {confirmStartOver && (
            <ConfirmDialog
              title="Move the file aside and start over?"
              confirmLabel="Move aside and start over"
              cancelLabel="Back"
              danger
              focusCancel
              onConfirm={startOver}
              onCancel={() => setConfirmStartOver(false)}
            >
              Keyorra renames the unreadable file and sets up a new, empty vault. Nothing is deleted.
            </ConfirmDialog>
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
        <h1>Keyorra is locked</h1>
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
        {canTouch && (
          <button type="button" onClick={touchUnlock} disabled={busy}>
            Unlock with Touch ID
          </button>
        )}
        {touchId?.enabled && touchId.passwordDue && (
          <p className="muted">Enter your master password. Keyorra asks for it every 14 days, then Touch ID works again.</p>
        )}
      </form>
    </div>
  );
}
