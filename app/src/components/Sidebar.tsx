import { useState, type FormEvent } from "react";
import type { Vault } from "../api";

export type Selection = { kind: "all" } | { kind: "favorites" } | { kind: "vault"; id: string } | { kind: "trash" };

interface Props {
  vaults: Vault[];
  selection: Selection;
  onSelect: (selection: Selection) => void;
  onNewVault: (name: string) => void;
  onImport: () => void;
  onLock: () => void;
  onSettings: () => void;
}

export function Sidebar({ vaults, selection, onSelect, onNewVault, onImport, onLock, onSettings }: Props) {
  const [naming, setNaming] = useState(false);
  const [name, setName] = useState("");
  const total = vaults.reduce((n, v) => n + v.itemCount, 0);
  const isCurrent = (s: Selection) =>
    s.kind === "vault" ? selection.kind === "vault" && selection.id === s.id : selection.kind === s.kind;

  function submit(e: FormEvent) {
    e.preventDefault();
    const trimmed = name.trim();
    if (!trimmed) return;
    onNewVault(trimmed);
    setName("");
    setNaming(false);
  }

  return (
    <nav className="sidebar" aria-label="Vaults">
      <div className="brand">Lockbox</div>
      <button className="nav" aria-current={isCurrent({ kind: "all" })} onClick={() => onSelect({ kind: "all" })}>
        <span>All items</span>
        <span className="muted">{total}</span>
      </button>
      <button className="nav" aria-current={isCurrent({ kind: "favorites" })} onClick={() => onSelect({ kind: "favorites" })}>
        Favorites
      </button>
      <button className="nav" aria-current={isCurrent({ kind: "trash" })} onClick={() => onSelect({ kind: "trash" })}>
        Recently Deleted
      </button>
      <div className="heading">Vaults</div>
      {vaults.map((v) => (
        <button
          key={v.id}
          className="nav"
          aria-current={isCurrent({ kind: "vault", id: v.id })}
          onClick={() => onSelect({ kind: "vault", id: v.id })}
        >
          <span>{v.name}</span>
          <span className="muted">{v.itemCount}</span>
        </button>
      ))}
      {naming ? (
        <form onSubmit={submit}>
          <input
            aria-label="Vault name"
            autoFocus
            value={name}
            onChange={(e) => setName(e.target.value)}
            onBlur={() => !name.trim() && setNaming(false)}
          />
        </form>
      ) : (
        <button className="nav muted" onClick={() => setNaming(true)}>
          + New vault
        </button>
      )}
      <div className="spacer" />
      <button className="nav" onClick={onImport}>
        Import from 1Password…
      </button>
      <button className="nav" onClick={onSettings}>
        Settings…
      </button>
      <button className="nav" onClick={onLock}>
        Lock
      </button>
    </nav>
  );
}
