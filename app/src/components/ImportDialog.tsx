import { open } from "@tauri-apps/plugin-dialog";
import { useEffect, useState } from "react";
import { api, errorMessage, type ImportPreview, type ImportResult } from "../api";

type Step = { kind: "pick" } | { kind: "preview"; preview: ImportPreview } | { kind: "done"; result: ImportResult };

export function ImportDialog({ onClose, onImported }: { onClose: () => void; onImported: () => void }) {
  const [step, setStep] = useState<Step>({ kind: "pick" });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  async function choose() {
    setError(null);
    setBusy(true);
    try {
      const path = await open({
        multiple: false,
        directory: false,
        filters: [{ name: "1Password export", extensions: ["1pux", "csv"] }],
      });
      if (typeof path !== "string") return;
      setStep({ kind: "preview", preview: await api.importPreview(path) });
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  async function apply() {
    setBusy(true);
    setError(null);
    try {
      const result = await api.importApply();
      setStep({ kind: "done", result });
      onImported();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="modal-backdrop">
      <div className="card modal" role="dialog" aria-modal="true" aria-labelledby="import-title">
        <h2 id="import-title">Import from 1Password</h2>
        {step.kind === "pick" && (
          <>
            <p className="muted">
              In 1Password choose File → Export, pick your account and the <b>1PUX</b> format (it keeps vaults,
              attachments and one-time codes). CSV works too but has less.
            </p>
            <button className="primary" onClick={choose} disabled={busy}>
              Choose export file…
            </button>
          </>
        )}
        {step.kind === "preview" && (
          <>
            <p>
              {step.preview.totalItems} items will be added as new vaults:
            </p>
            <ul>
              {step.preview.vaults.map((v) => (
                <li key={v.name}>
                  {v.name} — {v.items} items
                </li>
              ))}
            </ul>
            {step.preview.skipped.length > 0 && (
              <details open>
                <summary>{step.preview.skipped.length} not imported</summary>
                <ul>
                  {step.preview.skipped.map((s, i) => (
                    <li key={i}>
                      <b>{s.title}</b>: {s.reason}
                    </li>
                  ))}
                </ul>
              </details>
            )}
            <button className="primary" onClick={apply} disabled={busy}>
              Import {step.preview.totalItems} items
            </button>
          </>
        )}
        {step.kind === "done" && (
          <>
            <p>
              Imported {plural(step.result.items, "item")} into {plural(step.result.vaults, "vault")} ({plural(step.result.attachments, "attachment")}).
            </p>
            <p className="muted">Delete the export file now: it is not encrypted.</p>
            <button className="primary" onClick={onClose}>
              Done
            </button>
          </>
        )}
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        {step.kind !== "done" && (
          <button onClick={onClose} disabled={busy}>
            Cancel
          </button>
        )}
      </div>
    </div>
  );
}

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}
