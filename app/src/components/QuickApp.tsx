import { useEffect, useState } from "react";
import { api, type Status } from "../api";
import { QuickSearch } from "./QuickSearch";
import { Unlock } from "./Unlock";

/** Root of the ⌘⇧Space window (`index.html#quick`). */
export function QuickApp() {
  const [status, setStatus] = useState<Status | null>(null);
  // Remounts the search box each time the window opens, so it starts empty and focused.
  const [opened, setOpened] = useState(0);

  useEffect(() => {
    const refresh = () => api.status().then(setStatus);
    refresh();
    const subscriptions = [
      api.onLocked(() => setStatus("locked")),
      api.onUnlocked(() => setStatus("unlocked")),
      api.onQuickOpen(() => {
        refresh();
        setOpened((n) => n + 1);
      }),
    ];
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") void api.quickHide();
    };
    window.addEventListener("keydown", onKey);
    return () => {
      subscriptions.forEach((p) => p.then((stop) => stop()));
      window.removeEventListener("keydown", onKey);
    };
  }, []);

  if (status === null) return null;
  return (
    <div className="quick">
      {status === "unlocked" && <QuickSearch key={opened} onDone={() => void api.quickHide()} />}
      {status === "locked" && (
        <Unlock key={opened} onUnlocked={() => setStatus("unlocked")} onStartOver={() => setStatus("new")} />
      )}
      {status === "new" && <p className="empty">Set up Keyorra in its main window first.</p>}
    </div>
  );
}
