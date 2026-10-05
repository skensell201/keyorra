import { useCallback, useEffect, useState } from "react";
import { api, type Status } from "./api";
import { Main } from "./components/Main";
import { Setup } from "./components/Setup";
import { Unlock } from "./components/Unlock";

export function App() {
  const [status, setStatus] = useState<Status | null>(null);

  useEffect(() => {
    api.status().then(setStatus);
    const unlisten = api.onLocked(() => setStatus("locked"));
    return () => {
      unlisten.then((stop) => stop());
    };
  }, []);

  const lock = useCallback(async () => {
    await api.lock();
    setStatus("locked");
  }, []);

  if (status === null) return null;
  return (
    <>
      <div className="drag-region" data-tauri-drag-region />
      {status === "new" && <Setup onDone={() => setStatus("unlocked")} />}
      {status === "locked" && <Unlock onUnlocked={() => setStatus("unlocked")} onStartOver={() => setStatus("new")} />}
      {status === "unlocked" && <Main onLock={lock} />}
    </>
  );
}
