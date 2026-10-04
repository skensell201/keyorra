import { beforeEach, expect, test, vi } from "vitest";
import { renderPopup, type PopupDeps } from "./popup";

let deps: PopupDeps;

beforeEach(() => {
  document.body.innerHTML = `<main id="app"></main>`;
  deps = {
    ask: vi.fn(),
    activeTab: vi.fn().mockResolvedValue({ id: 7, url: "https://github.com/login" }),
    fillInTab: vi.fn().mockResolvedValue(undefined),
    close: vi.fn(),
    sleep: () => Promise.resolve(),
  };
});

const app = () => document.getElementById("app")!;

test("unpaired: connect shows the code and waits for approval", async () => {
  // The first status poll says "waiting" and the sleep is a real timer, so the code screen is observable.
  let polls = 0;
  deps.sleep = () => new Promise((r) => setTimeout(r, 120));
  vi.mocked(deps.ask).mockImplementation(async (m: any) => {
    if (m.type === "state") return { ok: true, value: "unpaired" };
    if (m.type === "pair") return { ok: true, value: { code: "381262" } };
    if (m.type === "pairStatus") return { ok: true, value: ++polls > 1 ? "paired" : "waiting" };
    if (m.type === "list") return { ok: true, value: [] };
    return { ok: true, value: undefined };
  });
  await renderPopup(app(), deps);
  expect(app().textContent).toContain("Connect this browser to Lockbox");
  (app().querySelector("button.primary") as HTMLButtonElement).click();
  await vi.waitFor(() => expect(app().textContent).toContain("381 262"));
  await vi.waitFor(() => expect(app().textContent).toContain("No logins for github.com"));
});

test("ready: lists logins and fills in the tab", async () => {
  vi.mocked(deps.ask).mockImplementation(async (m: any) => {
    if (m.type === "state") return { ok: true, value: "ready" };
    if (m.type === "list") return { ok: true, value: [{ id: "i1", title: "GitHub", username: "ivan", hasTotp: false }] };
    return { ok: true, value: undefined };
  });
  await renderPopup(app(), deps);
  await vi.waitFor(() => expect(app().textContent).toContain("GitHub"));
  (app().querySelector("button.item") as HTMLButtonElement).click();
  await vi.waitFor(() => expect(deps.fillInTab).toHaveBeenCalledWith(7, "i1"));
  expect(deps.close).toHaveBeenCalled();
});

test("locked and no app", async () => {
  vi.mocked(deps.ask).mockResolvedValue({ ok: true, value: "locked" });
  await renderPopup(app(), deps);
  expect(app().textContent).toContain("Lockbox is locked");
  vi.mocked(deps.ask).mockResolvedValue({ ok: true, value: "noApp" });
  await renderPopup(app(), deps);
  expect(app().textContent).toContain("Lockbox isn't running");
});

test("a pairing in progress shows its code again and resumes polling", async () => {
  let polls = 0;
  vi.mocked(deps.ask).mockImplementation(async (m: any) => {
    if (m.type === "state") return { ok: true, value: "pairing" };
    if (m.type === "pairingCode") return { ok: true, value: "381262" };
    if (m.type === "pairStatus") return { ok: true, value: ++polls > 1 ? "paired" : "waiting" };
    return { ok: true, value: [] };
  });
  deps.sleep = () => new Promise((r) => setTimeout(r, 120));
  const done = renderPopup(app(), deps);
  await vi.waitFor(() => expect(app().textContent).toContain("381 262"));
  await done;
  expect(app().textContent).toContain("No logins for github.com");
});

test("Connect is disabled after the first click", async () => {
  vi.mocked(deps.ask).mockImplementation(async (m: any) => {
    if (m.type === "state") return { ok: true, value: "unpaired" };
    if (m.type === "pair") return { ok: true, value: { code: "381262" } };
    return { ok: true, value: "waiting" };
  });
  deps.sleep = () => new Promise((r) => setTimeout(r, 1000));
  await renderPopup(app(), deps);
  const connect = app().querySelector("button.primary") as HTMLButtonElement;
  connect.click();
  expect(connect.disabled).toBe(true);
});

test("fill failures are explained", async () => {
  vi.mocked(deps.ask).mockImplementation(async (m: any) => {
    if (m.type === "state") return { ok: true, value: "ready" };
    return { ok: true, value: [{ id: "i1", title: "GitHub", username: "ivan", hasTotp: false }] };
  });
  vi.mocked(deps.fillInTab).mockRejectedValueOnce(new Error("no receiver"));
  await renderPopup(app(), deps);
  await vi.waitFor(() => expect(app().querySelector("button.item")).not.toBeNull());
  (app().querySelector("button.item") as HTMLButtonElement).click();
  await vi.waitFor(() => expect(app().textContent).toContain("Reload this page to fill"));

  vi.mocked(deps.fillInTab).mockResolvedValueOnce({ filled: 0 });
  await renderPopup(app(), deps);
  await vi.waitFor(() => expect(app().querySelector("button.item")).not.toBeNull());
  (app().querySelector("button.item") as HTMLButtonElement).click();
  await vi.waitFor(() => expect(app().textContent).toContain("No login fields found"));
});

test("non-web tabs get a hint instead of a list", async () => {
  vi.mocked(deps.activeTab).mockResolvedValue({ id: 1, url: "chrome://extensions" });
  vi.mocked(deps.ask).mockResolvedValue({ ok: true, value: "ready" });
  await renderPopup(app(), deps);
  expect(app().textContent).toContain("Open a website to fill a login.");
});

test("pairing without a stored code says it is waiting; a vanished pairing returns to Connect", async () => {
  let state = "pairing";
  vi.mocked(deps.ask).mockImplementation(async (m: any) => {
    if (m.type === "state") return { ok: true, value: state };
    if (m.type === "pairingCode") return { ok: true, value: null };
    if (m.type === "pairStatus") {
      state = "unpaired";
      return { ok: true, value: "none" };
    }
    return { ok: true, value: [] };
  });
  const done = renderPopup(app(), deps);
  await vi.waitFor(() => expect(app().textContent).toContain("Connect this browser to Lockbox"));
  await done;
});
