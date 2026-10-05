import { useState } from "react";
import { api, errorMessage, type PairingRequest } from "../api";

export function PairingDialog({ request, onDone }: { request: PairingRequest; onDone: () => void }) {
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function answer(approve: boolean) {
    setBusy(true);
    setError(null);
    try {
      if (approve) await api.approvePairing(request.clientId);
      else await api.denyPairing(request.clientId);
      onDone();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="modal-backdrop">
      <div className="card modal pairing" role="dialog" aria-modal="true" aria-labelledby="pair-title">
        <h2 id="pair-title">Connect {request.name}?</h2>
        <p className="muted">Check that the Keyorra extension in {request.name} shows the same code.</p>
        <p className="pair-code mono">{`${request.code.slice(0, 3)} ${request.code.slice(3)}`}</p>
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        <div className="modal-actions">
          <button onClick={() => answer(false)} disabled={busy}>
            Deny
          </button>
          <button className="primary" onClick={() => answer(true)} disabled={busy}>
            Connect
          </button>
        </div>
      </div>
    </div>
  );
}
