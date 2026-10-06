import { useState } from "react";
import { api, errorMessage, type EmergencyKit as Kit } from "../api";

/** Formats an account id (32 hex digits) in groups of four for reading aloud or copying. */
export function groupHex(hex: string) {
  return hex.match(/.{1,4}/g)?.join(" ") ?? hex;
}

/**
 * The Emergency Kit (spec §7.6): printing is the main action. The page holds the Secret Key:
 * it must not end up next to the encrypted data.
 */
export function EmergencyKit({ kit, location, onDone }: { kit: Kit; location: string | null; onDone: () => void }) {
  const [note, setNote] = useState("");
  async function copySetupCode() {
    try {
      await api.copySecret(kit.setupCode);
      setNote("Setup code copied. It clears from the clipboard in 90 seconds.");
    } catch (e) {
      setNote(errorMessage(e));
    }
  }
  return (
    <section className="modal-section kit" aria-label="Emergency Kit">
      <h3>Emergency Kit</h3>
      <p className="muted">
        Print this page and keep it with your important papers. With it and your master password you can reach your
        data on a new Mac if you lose all your devices. Without it, nobody can — not even us.
      </p>
      <dl className="kit-sheet">
        <dt>Account</dt>
        <dd className="mono">{groupHex(kit.accountId)}</dd>
        <dt>Secret Key</dt>
        <dd className="mono" data-testid="secret-key">
          {kit.secretKey}
        </dd>
        {location && (
          <>
            <dt>Sync folder</dt>
            <dd className="mono">{location}</dd>
          </>
        )}
        <dt>Master password</dt>
        <dd className="kit-blank">&nbsp;</dd>
      </dl>
      <p className="muted">
        Don't save the kit as a file in iCloud Drive, Dropbox or your sync folder: next to the encrypted data it would
        undo what the Secret Key protects.
      </p>
      <div className="modal-actions">
        <span className="status" role="status" aria-label="Emergency Kit">
          {note}
        </span>
        <button className="secondary" onClick={copySetupCode}>
          Copy setup code
        </button>
        <button className="secondary" onClick={onDone}>
          Done
        </button>
        <button className="primary" onClick={() => window.print()}>
          Print
        </button>
      </div>
    </section>
  );
}
