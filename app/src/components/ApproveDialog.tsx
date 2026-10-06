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
