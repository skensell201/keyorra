import { useEffect, useState } from "react";
import { api, type SyncScreen } from "../api";

/**
 * Above the item list: devices waiting for the main Mac's approval, sync that stopped, and
 * changes not yet confirmed by the main Mac. Refreshes on every round.
 */
export function SyncBanner({ onOpen, onSynced }: { onOpen: () => void; onSynced?: () => void }) {
  const [screen, setScreen] = useState<SyncScreen | null>(null);
  useEffect(() => {
    const load = () =>
      api
        .syncScreen()
        .then(setScreen)
        .catch(() => setScreen(null));
    void load();
    const subscriptions = [
      api.onSynced(() => {
        void load();
        onSynced?.();
      }),
      api.onSyncApproval(() => void load()),
    ];
    return () => {
      subscriptions.forEach((p) => p.then((stop) => stop()));
    };
  }, [onSynced]);

  if (!screen?.enabled) return null;
  const status = screen.status;
  const waiting = status?.mainDevice ? status.devices.filter((d) => !d.approved).length : 0;
  const message =
    waiting > 0
      ? `${waiting} device${waiting === 1 ? "" : "s"} asked to join your account`
      : screen.alarms.length > 0
        ? "Sync needs your attention"
        : screen.error
          ? `Sync stopped: ${screen.error}`
          : status && !status.mainDevice && !status.rootConfirmed
            ? "Changes from other devices aren't confirmed by your main Mac yet"
            : null;
  if (!message) return null;
  return (
    <div className="banner sync-banner" role="status">
      {message}
      <button onClick={onOpen}>{waiting > 0 ? "Review" : "Open Sync"}</button>
    </div>
  );
}
