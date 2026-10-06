import type { SyncScreen } from "../api";

/** A synced main Mac with one approved laptop, as the Sync screen gets it. */
export function syncScreen(overrides: Partial<SyncScreen> = {}): SyncScreen {
  return {
    enabled: true,
    running: true,
    error: null,
    location: "/Users/a/Library/Mobile Documents/com~apple~CloudDocs/Keyorra/0101",
    lastRoundAt: 1_790_000_000,
    lastRoundOk: true,
    status: {
      mainDevice: true,
      waitingForApproval: false,
      keyCode: "0a1b-2c3d-4e5f",
      devices: [
        { id: "d0", name: "Main Mac", approved: true, main: true, thisDevice: true, removed: false },
        { id: "d1", name: "Laptop", approved: true, main: false, thisDevice: false, removed: false },
      ],
      alarms: 0,
      rootConfirmed: true,
    },
    alarms: [],
    notices: [],
    log: [{ at: 1_790_000_000, text: "Received 2 change(s) from Laptop" }],
    ...overrides,
  };
}
