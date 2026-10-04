import { Keyhole } from "./Keyhole";
import { useState, type FormEvent } from "react";
import { api, errorMessage } from "../api";

const MIN_LENGTH = 10;

export function Setup({ onDone }: { onDone: () => void }) {
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const tooShort = password.length > 0 && password.length < MIN_LENGTH;
  const mismatch = confirm.length > 0 && confirm !== password;
  const valid = password.length >= MIN_LENGTH && confirm === password;

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!valid) return;
    setBusy(true);
    setError(null);
    try {
      await api.create(password);
      onDone();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="center">
      <form className="card auth" onSubmit={submit}>
        <div className="logo">
          <Keyhole width={24} height={24} />
        </div>
        <h1>Create your Lockbox</h1>
        <p className="muted">
          Your master password encrypts everything. It can't be recovered, so write it down and keep it somewhere safe.
        </p>
        <label>
          Master password
          <input type="password" autoFocus value={password} onChange={(e) => setPassword(e.target.value)} />
        </label>
        {tooShort && <p className="error">Use at least {MIN_LENGTH} characters</p>}
        <label>
          Confirm password
          <input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
        </label>
        {mismatch && <p className="error">Passwords don't match</p>}
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        <button className="primary" type="submit" disabled={!valid || busy}>
          {busy ? "Creating…" : "Create vault"}
        </button>
      </form>
    </div>
  );
}
