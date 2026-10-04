import { useState } from "react";
import { api, errorMessage, type ItemSummary } from "../api";
import { KIND_LABEL } from "../format";

export function TrashItem({ item, onRestored }: { item: ItemSummary; onRestored: () => void }) {
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function restore() {
    setBusy(true);
    setError(null);
    try {
      await api.restoreItem(item.id);
      onRestored();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <article className="item-detail">
      <header>
        <div>
          <span className="kind">{item.kind ? KIND_LABEL[item.kind] : "Item"}</span>
          <h2>{item.title || "Untitled"}</h2>
        </div>
        <div className="actions">
          <button className="primary" onClick={restore} disabled={busy}>
            Restore
          </button>
        </div>
      </header>
      {error && (
        <div className="banner error" role="alert">
          {error}
        </div>
      )}
      <p className="muted">
        This item is in Recently Deleted. Items here are removed for good 30 days after they were deleted.
      </p>
    </article>
  );
}
