import { useCallback, useEffect, useState } from "react";
import { api, type Status } from "./api";
import { Main } from "./components/Main";
import { Setup } from "./components/Setup";
import { Unlock } from "./components/Unlock";

export function App() {
  const [status, setStatus] = useState<Status | null>(null);
  const [justLocked, setJustLocked] = useState(false);

  useEffect(() => {
    api.status().then(setStatus);
    const subscriptions = [
      api.onLocked(() => setStatus("locked")),
      // Unlocked from the quick-search window.
      api.onUnlocked(() => setStatus((s) => (s === "locked" ? "unlocked" : s))),
    ];
    return () => {
      subscriptions.forEach((p) => p.then((stop) => stop()));
    };
  }, []);

  const lock = useCallback(async () => {
    await api.lock();
    setJustLocked(true);
    setStatus("locked");
  }, []);

  if (status === null) return null;
  return (
    <>
      <div className="drag-region" data-tauri-drag-region />
      {status === "new" && <Setup onDone={() => setStatus("unlocked")} />}
      {status === "locked" && (
        <Unlock
          justLocked={justLocked}
          onUnlocked={() => {
            setJustLocked(false);
            setStatus("unlocked");
          }}
          onStartOver={() => setStatus("new")}
        />
      )}
      {status === "unlocked" && <Main onLock={lock} />}
    </>
  );
}
