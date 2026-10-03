import { useCallback, useEffect, useState } from "react";
import { api, errorMessage, type Item, type ItemKind, type ItemSummary, type Vault } from "../api";
import { ImportDialog } from "./ImportDialog";
import { ItemDetail } from "./ItemDetail";
import { ItemEditor } from "./ItemEditor";
import { ItemList } from "./ItemList";
import { Sidebar, type Selection } from "./Sidebar";

type Pane = { mode: "empty" } | { mode: "view"; id: string } | { mode: "edit"; item: Item };

export function Main({ onLock }: { onLock: () => void }) {
  const [vaults, setVaults] = useState<Vault[]>([]);
  const [selection, setSelection] = useState<Selection>({ kind: "all" });
  const [query, setQuery] = useState("");
  const [items, setItems] = useState<ItemSummary[]>([]);
  const [pane, setPane] = useState<Pane>({ mode: "empty" });
  const [importing, setImporting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadVaults = useCallback(
    () => api.vaults().then(setVaults).catch((e) => setError(errorMessage(e))),
    [],
  );
  const loadItems = useCallback(
    () =>
      api
        .items({
          query,
          vaultId: selection.kind === "vault" ? selection.id : null,
          favorites: selection.kind === "favorites",
        })
        .then(setItems)
        .catch((e) => setError(errorMessage(e))),
    [query, selection],
  );
  const refresh = useCallback(() => Promise.all([loadVaults(), loadItems()]), [loadVaults, loadItems]);

  useEffect(() => {
    loadVaults();
  }, [loadVaults]);
  useEffect(() => {
    loadItems();
  }, [loadItems]);

  const targetVault = selection.kind === "vault" ? selection.id : vaults[0]?.id;

  async function newItem(kind: ItemKind) {
    if (!targetVault) return;
    try {
      setPane({ mode: "edit", item: await api.newItem(targetVault, kind) });
    } catch (e) {
      setError(errorMessage(e));
    }
  }

  async function newVault(name: string) {
    try {
      await api.createVault(name);
      await loadVaults();
    } catch (e) {
      setError(errorMessage(e));
    }
  }

  return (
    <div className="app">
      <Sidebar
        vaults={vaults}
        selection={selection}
        onSelect={(s) => {
          setSelection(s);
          setPane({ mode: "empty" });
        }}
        onNewVault={newVault}
        onImport={() => setImporting(true)}
        onLock={onLock}
      />
      <ItemList
        items={items}
        query={query}
        onQuery={setQuery}
        selectedId={pane.mode === "view" ? pane.id : null}
        onSelect={(id) => setPane({ mode: "view", id })}
        onNew={newItem}
        canCreate={Boolean(targetVault)}
      />
      <section className="detail">
        {error && (
          <div className="banner error" role="alert">
            {error}
            <button onClick={() => setError(null)}>Dismiss</button>
          </div>
        )}
        {pane.mode === "empty" && <p className="empty">Select an item</p>}
        {pane.mode === "view" && (
          <ItemDetail
            key={pane.id}
            itemId={pane.id}
            onEdit={(item) => setPane({ mode: "edit", item })}
            onDeleted={async () => {
              setPane({ mode: "empty" });
              await refresh();
            }}
          />
        )}
        {pane.mode === "edit" && (
          <ItemEditor
            key={pane.item.id}
            item={pane.item}
            onCancel={() =>
              setPane(items.some((i) => i.id === pane.item.id) ? { mode: "view", id: pane.item.id } : { mode: "empty" })
            }
            onSave={async (saved) => {
              setPane({ mode: "view", id: saved.id });
              await refresh();
            }}
          />
        )}
      </section>
      {importing && <ImportDialog onClose={() => setImporting(false)} onImported={refresh} />}
    </div>
  );
}
