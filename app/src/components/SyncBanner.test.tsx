import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { api } from "../api";
import { syncScreen } from "../test/sync";
import { SyncBanner } from "./SyncBanner";

vi.mock("../api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api")>();
  return {
    ...actual,
    api: { ...actual.api, syncScreen: vi.fn(), onSynced: vi.fn(), onSyncApproval: vi.fn() },
  };
});

let synced: (() => void) | null = null;
beforeEach(() => {
  synced = null;
  vi.mocked(api.onSynced).mockReset().mockImplementation(async (cb) => {
    synced = cb;
    return () => {};
  });
  vi.mocked(api.onSyncApproval).mockReset().mockResolvedValue(() => {});
});

test("nothing while all is well", async () => {
  vi.mocked(api.syncScreen).mockReset().mockResolvedValue(syncScreen());
  const { container } = render(<SyncBanner onOpen={vi.fn()} />);
  await act(async () => {});
  expect(container).toBeEmptyDOMElement();
});

test("devices waiting for approval, after a round", async () => {
  const user = userEvent.setup();
  const waiting = syncScreen();
  waiting.status!.devices.push({ id: "d2", name: "New Mac", approved: false, main: false, thisDevice: false, removed: false });
  vi.mocked(api.syncScreen).mockReset().mockResolvedValueOnce(syncScreen()).mockResolvedValue(waiting);
  const onOpen = vi.fn();
  const onSynced = vi.fn();
  render(<SyncBanner onOpen={onOpen} onSynced={onSynced} />);
  await act(async () => synced?.());
  expect(onSynced).toHaveBeenCalled();
  expect(await screen.findByRole("status")).toHaveTextContent("1 device asked to join your account");
  await user.click(screen.getByRole("button", { name: "Review" }));
  expect(onOpen).toHaveBeenCalled();
});

test("changes not yet confirmed by the main Mac", async () => {
  const s = syncScreen();
  s.status = { ...s.status!, mainDevice: false, rootConfirmed: false };
  vi.mocked(api.syncScreen).mockReset().mockResolvedValue(s);
  render(<SyncBanner onOpen={vi.fn()} />);
  expect(await screen.findByRole("status")).toHaveTextContent("aren't confirmed by your main Mac yet");
});
