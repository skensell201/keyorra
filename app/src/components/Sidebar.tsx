import { IconGrid, IconImport, IconLock, IconPencil, IconPlus, IconSettings, IconShield, IconStar, IconTrash, IconVault } from "./icons";
import { Keyhole } from "./Keyhole";
import { useState, type FormEvent } from "react";
import type { Vault } from "../api";

export type Selection = { kind: "all" } | { kind: "favorites" } | { kind: "vault"; id: string } | { kind: "trash" } | { kind: "watchtower" };

interface Props {
  vaults: Vault[];
  selection: Selection;
  /** Items with Watchtower findings; hidden while unknown. */
  watchtowerCount?: number;
  onSelect: (selection: Selection) => void;
  onNewVault: (name: string) => void;
  onRenameVault: (id: string, name: string) => void;
  onDeleteVault: (vault: Vault) => void;
  onImport: () => void;
  onLock: () => void;
  onSettings: () => void;
}

export function Sidebar(props: Props) {
  const { vaults, selection, watchtowerCount, onSelect, onNewVault, onRenameVault, onDeleteVault, onImport, onLock, onSettings } = props;
  const [renaming, setRenaming] = useState<string | null>(null);
  const [newName, setNewName] = useState("");
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

  function submitRename(e: FormEvent, id: string) {
    e.preventDefault();
    const trimmed = newName.trim();
    if (trimmed) onRenameVault(id, trimmed);
    setRenaming(null);
  }

  return (
    <nav className="sidebar" aria-label="Vaults">
      <div className="brand">
        <Keyhole />
        Keyorra
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
      <button className="nav" aria-current={isCurrent({ kind: "watchtower" })} onClick={() => onSelect({ kind: "watchtower" })}>
        <IconShield />
        <span>Watchtower</span>
        {watchtowerCount !== undefined && <span className="count">{watchtowerCount}</span>}
      </button>
      <div className="heading">Vaults</div>
      {vaults.map((v) =>
        renaming === v.id ? (
          <form key={v.id} onSubmit={(e) => submitRename(e, v.id)}>
            <input
              aria-label={`New name for ${v.name}`}
              autoFocus
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              onKeyDown={(e) => e.key === "Escape" && setRenaming(null)}
              onBlur={() => setRenaming(null)}
            />
          </form>
        ) : (
          <div key={v.id} className="vault-row">
            <button
              className="nav"
              aria-current={isCurrent({ kind: "vault", id: v.id })}
              onClick={() => onSelect({ kind: "vault", id: v.id })}
            >
              <IconVault />
              <span>{v.name}</span>
              <span className="count">{v.itemCount}</span>
            </button>
            {isCurrent({ kind: "vault", id: v.id }) && (
              <span className="vault-actions">
                <button
                  className="icon"
                  title="Rename"
                  aria-label={`Rename ${v.name}`}
                  onClick={() => {
                    setNewName(v.name);
                    setRenaming(v.id);
                  }}
                >
                  <IconPencil />
                </button>
                <button className="icon" title="Delete" aria-label={`Delete ${v.name}`} onClick={() => onDeleteVault(v)}>
                  <IconTrash />
                </button>
              </span>
            )}
          </div>
        ),
      )}
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
