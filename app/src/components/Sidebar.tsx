import { IconGrid, IconImport, IconLock, IconPlus, IconSettings, IconStar, IconTrash, IconVault } from "./icons";
import { Keyhole } from "./Keyhole";
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
      <div className="brand">
        <Keyhole />
        Keepsake
      </div>
      <button className="nav" aria-current={isCurrent({ kind: "all" })} onClick={() => onSelect({ kind: "all" })}>
        <IconGrid />
        <span>All items</span>
        <span className="count">{total}</span>
      </button>
      <button className="nav" aria-current={isCurrent({ kind: "favorites" })} onClick={() => onSelect({ kind: "favorites" })}>
        <IconStar />
        Favorites
      </button>
      <button className="nav" aria-current={isCurrent({ kind: "trash" })} onClick={() => onSelect({ kind: "trash" })}>
        <IconTrash />
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
          <IconVault />
          <span>{v.name}</span>
          <span className="count">{v.itemCount}</span>
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
        <button className="nav" aria-label="+ New vault" onClick={() => setNaming(true)}>
          <IconPlus />
          New vault
        </button>
      )}
      <div className="spacer" />
      <button className="nav" onClick={onImport}>
        <IconImport />
        Import…
      </button>
      <button className="nav" onClick={onSettings}>
        <IconSettings />
        Settings…
      </button>
      <button className="nav" onClick={onLock}>
        <IconLock />
        Lock
      </button>
    </nav>
  );
}
