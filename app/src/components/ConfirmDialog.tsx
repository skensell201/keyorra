import { useEffect, type ReactNode } from "react";

interface Props {
  title: string;
  children: ReactNode;
  confirmLabel: string;
  /** Defaults to "Cancel". */
  cancelLabel?: string;
  danger?: boolean;
  /** Focus the safe choice, so a repeated click or Enter can't confirm by accident. */
  focusCancel?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

/** A small yes/no dialog; Escape cancels. */
export function ConfirmDialog({
  title,
  children,
  confirmLabel,
  cancelLabel = "Cancel",
  danger,
  focusCancel,
  onConfirm,
  onCancel,
}: Props) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onCancel();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onCancel]);

  return (
    <div className="modal-backdrop">
      <div className="card modal confirm" role="alertdialog" aria-modal="true" aria-labelledby="confirm-title">
        <h2 id="confirm-title">{title}</h2>
        <div className="muted">{children}</div>
        <div className="modal-actions">
          <button autoFocus={focusCancel} onClick={onCancel}>
            {cancelLabel}
          </button>
          <button className={danger ? "danger" : "primary"} autoFocus={!focusCancel} onClick={onConfirm}>
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
