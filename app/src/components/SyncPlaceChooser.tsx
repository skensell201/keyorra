import { open } from "@tauri-apps/plugin-dialog";
import { useEffect, useState } from "react";
import { api, errorMessage, type SyncPlace } from "../api";
import { PathText } from "./PathText";

/**
 * Where synced accounts live: iCloud Drive unless another folder is chosen. Used before
 * turning sync on and before joining (also on first run, without a vault yet).
 * `onPlace` tells the parent whether there is a place to use.
 */
export function SyncPlaceChooser({ onPlace }: { onPlace?: (place: SyncPlace | null) => void }) {
  const [place, setPlace] = useState<SyncPlace | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);

  function update(p: SyncPlace | null) {
    setPlace(p);
    onPlace?.(p);
  }
  useEffect(() => {
    api
      .syncPlace()
      .then((p) => update(p))
      .catch(() => update(null))
      .finally(() => setLoaded(true));
    // Once, when shown.
  }, []);

  async function choose(path: string | null) {
    setError(null);
    try {
      update(await api.setSyncPlace(path));
    } catch (e) {
      setError(errorMessage(e));
    }
  }
  async function chooseFolder() {
    const picked = await open({ directory: true, multiple: false, title: "Where Keyorra keeps synced accounts" });
    if (typeof picked === "string") await choose(picked);
  }

  return (
    <section className="modal-section" aria-label="Where">
      <h3>Where</h3>
      {place ? (
        <>
          <PathText path={place.path} label="folder path" />
          {place.warning && <p className="muted">{place.warning}</p>}
        </>
      ) : (
        loaded && (
          <p className="muted">iCloud Drive isn't set up on this Mac. Choose a folder that a sync app keeps in step.</p>
        )
      )}
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      <div className="modal-actions">
        {place && place.kind !== "icloud" && (
          <button type="button" className="secondary" onClick={() => choose(null)}>
            Use iCloud Drive
          </button>
        )}
        <button type="button" className="secondary" onClick={chooseFolder}>
          Choose another folder
        </button>
      </div>
    </section>
  );
}
