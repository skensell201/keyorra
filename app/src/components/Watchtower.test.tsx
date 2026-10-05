import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, test, vi } from "vitest";
import { api, watchtowerCount, type ItemSummary, type WatchtowerReport } from "../api";
import { Watchtower } from "./Watchtower";

vi.mock("../api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api")>();
  return { ...actual, api: { ...actual.api, checkBreaches: vi.fn() } };
});

const summary = (id: string, title: string): ItemSummary => ({
  id, vaultId: "v1", kind: "login", title, subtitle: "", favorite: false, hasTotp: false, updatedAt: 0, damaged: false,
});

const report: WatchtowerReport = {
  breached: [],
  reused: [
    { item: summary("a", "Bank"), detail: "Same password as 1 other item" },
    { item: summary("b", "Shop"), detail: "Same password as 1 other item" },
  ],
  weak: [{ item: summary("b", "Shop"), detail: "Weak password (strength 1 of 4)" }],
  missingTwoFactor: [{ item: summary("c", "GitHub"), detail: "github.com offers one-time passwords" }],
  breachesChecked: false,
  uncheckedPasswords: 2,
};

beforeEach(() => {
  vi.mocked(api.checkBreaches).mockReset();
});

test("counts per category and opens an item", async () => {
  const user = userEvent.setup();
  const onOpen = vi.fn();
  render(<Watchtower report={report} selectedId={null} onOpen={onOpen} onReport={vi.fn()} />);
  expect(screen.getByRole("tab", { name: "Compromised (–)" })).toHaveAttribute("aria-selected", "true");
  expect(screen.getByRole("tab", { name: "Weak (1)" })).toBeInTheDocument();
  expect(screen.getByRole("tab", { name: "Missing 2FA (1)" })).toBeInTheDocument();
  await user.click(screen.getByRole("tab", { name: "Reused (2)" }));
  const list = screen.getByRole("list", { name: "Reused" });
  expect(within(list).getAllByRole("button").map((b) => b.textContent)).toEqual([
    "BankSame password as 1 other item",
    "ShopSame password as 1 other item",
  ]);
  await user.click(within(list).getByRole("button", { name: /Shop/ }));
  expect(onOpen).toHaveBeenCalledWith("b");
});

test("breach check is opt-in and explains k-anonymity", async () => {
  const user = userEvent.setup();
  const onReport = vi.fn();
  const checked = { ...report, breachesChecked: true, uncheckedPasswords: 0, breached: [{ item: summary("a", "Bank"), detail: "Found 12 times in data breaches" }] };
  vi.mocked(api.checkBreaches).mockResolvedValue(checked);
  render(<Watchtower report={report} selectedId={null} onOpen={vi.fn()} onReport={onReport} />);
  expect(screen.getByText(/first 5 characters of each password's SHA-1 hash/)).toBeInTheDocument();
  expect(api.checkBreaches).not.toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Check for breaches" }));
  await waitFor(() => expect(onReport).toHaveBeenCalledWith(checked));
});

test("a failed breach check shows the error", async () => {
  const user = userEvent.setup();
  vi.mocked(api.checkBreaches).mockRejectedValue({ kind: "other", message: "Couldn't reach Have I Been Pwned: timeout" });
  render(<Watchtower report={report} selectedId={null} onOpen={vi.fn()} onReport={vi.fn()} />);
  await user.click(screen.getByRole("button", { name: "Check for breaches" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Couldn't reach Have I Been Pwned");
});

test("after the check, an empty category says so", () => {
  const clean = { ...report, breachesChecked: true, uncheckedPasswords: 0 };
  render(<Watchtower report={clean} selectedId={null} onOpen={vi.fn()} onReport={vi.fn()} />);
  expect(screen.getByRole("tab", { name: "Compromised (0)" })).toBeInTheDocument();
  expect(screen.getByText("No passwords found in known breaches")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Check for breaches" })).not.toBeInTheDocument();
});

test("watchtowerCount counts each item once", () => {
  expect(watchtowerCount(report)).toBe(3);
});
