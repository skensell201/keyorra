import { useEffect, useState, type FormEvent } from "react";
import { api, errorMessage, isCmdError, type JoinOutcome, type SyncPlace } from "../api";
import { SyncPlaceChooser } from "./SyncPlaceChooser";

/**
 * Joining a synced account with the master password and the setup code shown on a Mac that
 * is set up (or the Secret Key from the Emergency Kit). Then this Mac waits until the main
 * Mac approves it, comparing the code shown here.
 */
export function JoinSync({
  onJoined,
  onCancel,
  onBusy,
}: {
  onJoined: (outcome: JoinOutcome) => void;
  onCancel?: () => void;
  onBusy?: (busy: boolean) => void;
}) {
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // The account is looked for in the sync place: iCloud Drive or a chosen folder.
  const [place, setPlace] = useState<SyncPlace | null>(null);
  useEffect(() => onBusy?.(busy), [busy, onBusy]);
  const valid = password.length > 0 && code.trim().length > 0 && !busy && place !== null;

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
    <>
      <SyncPlaceChooser onPlace={setPlace} />
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
    </>
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
