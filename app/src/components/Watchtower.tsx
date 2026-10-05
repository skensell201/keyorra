import { useState } from "react";
import { api, errorMessage, type WatchtowerReport } from "../api";

type Category = "breached" | "reused" | "weak" | "missingTwoFactor";

const CATEGORIES: { key: Category; label: string; empty: string }[] = [
  { key: "breached", label: "Compromised", empty: "No passwords found in known breaches" },
  { key: "reused", label: "Reused", empty: "No password is used twice" },
  { key: "weak", label: "Weak", empty: "No weak passwords" },
  { key: "missingTwoFactor", label: "Missing 2FA", empty: "No known sites without a one-time password" },
];

interface Props {
  report: WatchtowerReport | null;
  selectedId: string | null;
  onOpen: (id: string) => void;
  onReport: (report: WatchtowerReport) => void;
}

/** The middle column in Watchtower mode: problem categories and the affected items. */
export function Watchtower({ report, selectedId, onOpen, onReport }: Props) {
  const [category, setCategory] = useState<Category>("breached");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function check() {
    setBusy(true);
    setError(null);
    try {
      onReport(await api.checkBreaches());
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  const current = CATEGORIES.find((c) => c.key === category)!;
  const findings = report?.[category] ?? [];
  const notChecked = report !== null && !report.breachesChecked;

  return (
    <section className="list watchtower" aria-label="Watchtower">
      <div className="toolbar">
        <h2>Watchtower</h2>
      </div>
      {report === null ? (
        <p className="empty">Checking your passwords…</p>
      ) : (
        <>
          <div className="categories" role="tablist" aria-label="Problems">
            {CATEGORIES.map((c) => {
              const count = c.key === "breached" && notChecked && report.breached.length === 0 ? "–" : report[c.key].length;
              return (
                <button
                  key={c.key}
                  role="tab"
                  aria-selected={category === c.key}
                  aria-label={`${c.label} (${count})`}
                  onClick={() => setCategory(c.key)}
                >
                  <span className="count">{count}</span>
                  <span>{c.label}</span>
                </button>
              );
            })}
          </div>
          {category === "breached" && notChecked && (
            <div className="breach-check">
              <p>
                Check your passwords against the Have I Been Pwned list of breached passwords. Only the first 5 characters
                of each password's SHA-1 hash are sent (k-anonymity): your passwords never leave this Mac.
              </p>
              <button className="primary" onClick={check} disabled={busy}>
                {busy ? "Checking…" : "Check for breaches"}
              </button>
              {error && (
                <p className="error" role="alert">
                  {error}
                </p>
              )}
            </div>
          )}
          {findings.length === 0 ? (
            !(category === "breached" && notChecked) && <p className="empty">{current.empty}</p>
          ) : (
            <ul aria-label={current.label}>
              {findings.map((f) => (
                <li key={f.item.id}>
                  <button aria-current={f.item.id === selectedId} onClick={() => onOpen(f.item.id)}>
                    <span className="text">
                      <span>{f.item.title || "Untitled"}</span>
                      <span className="subtitle">{f.detail}</span>
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </>
      )}
    </section>
  );
}
