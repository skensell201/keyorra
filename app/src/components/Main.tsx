import { useCallback, useEffect, useRef, useState } from "react";
import { api, errorMessage, type Item, type ItemKind, type ItemSummary, type PairingRequest, type Vault } from "../api";
import { ImportDialog } from "./ImportDialog";
import { ItemDetail } from "./ItemDetail";
import { ItemEditor } from "./ItemEditor";
import { PairingDialog } from "./PairingDialog";
import { ItemList } from "./ItemList";
import { TrashItem } from "./TrashItem";
import { SettingsDialog } from "./SettingsDialog";
import { Sidebar, type Selection } from "./Sidebar";

type Pane = { mode: "empty" } | { mode: "view"; id: string } | { mode: "edit"; item: Item; isNew: boolean };

export function Main({ onLock }: { onLock: () => void }) {
  const [vaults, setVaults] = useState<Vault[]>([]);
  const [selection, setSelection] = useState<Selection>({ kind: "all" });
  const [query, setQuery] = useState("");
  const [items, setItems] = useState<ItemSummary[]>([]);
  const [pane, setPane] = useState<Pane>({ mode: "empty" });
  const [importing, setImporting] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pairing, setPairing] = useState<PairingRequest | null>(null);

  const vaultsSeq = useRef(0);
  const itemsSeq = useRef(0);

  const loadVaults = useCallback(() => {
    const seq = ++vaultsSeq.current;
    return api
      .vaults()
      .then((v) => {
        if (seq !== vaultsSeq.current) return;
        setVaults(v);
        setError(null);
      })
      .catch((e) => {
        if (seq === vaultsSeq.current) setError(errorMessage(e));
      });
  }, []);
  const loadItems = useCallback(() => {
    const seq = ++itemsSeq.current;
    const request =
      selection.kind === "trash"
        ? api.deletedItems().then((list) => {
            const q = query.trim().toLowerCase();
            return list.filter((i) => !q || i.title.toLowerCase().includes(q));
          })
        : api.items({
            query,
            vaultId: selection.kind === "vault" ? selection.id : null,
            favorites: selection.kind === "favorites",
          });
    return request
      .then((list) => {
        if (seq !== itemsSeq.current) return;
        setItems(list);
        setError(null);
      })
      .catch((e) => {
        if (seq === itemsSeq.current) setError(errorMessage(e));
      });
  }, [query, selection]);
  const refresh = useCallback(() => Promise.all([loadVaults(), loadItems()]), [loadVaults, loadItems]);

  useEffect(() => {
    const unlisten = api.onPairRequest(setPairing);
    return () => {
      unlisten.then((stop) => stop());
    };
  }, []);
  useEffect(() => {
    loadVaults();
  }, [loadVaults]);
  useEffect(() => {
    loadItems();
  }, [loadItems]);

  const targetVault =
    selection.kind === "vault" ? selection.id : selection.kind === "trash" ? undefined : vaults[0]?.id;

  async function newItem(kind: ItemKind) {
    if (!targetVault) return;
    try {
      setPane({ mode: "edit", item: await api.newItem(targetVault, kind), isNew: true });
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
        onSettings={() => setShowSettings(true)}
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
        {pane.mode === "view" && selection.kind === "trash" && (
          <TrashPane
            key={pane.id}
            item={items.find((i) => i.id === pane.id)}
            onRestored={async () => {
              setPane({ mode: "empty" });
              await refresh();
            }}
          />
        )}
        {pane.mode === "view" && selection.kind !== "trash" && (
          <ItemDetail
            key={pane.id}
            itemId={pane.id}
            onEdit={(item) => setPane({ mode: "edit", item, isNew: false })}
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
            isNew={pane.isNew}
            onCancel={() => setPane(pane.isNew ? { mode: "empty" } : { mode: "view", id: pane.item.id })}
            onSave={async (saved) => {
              setPane({ mode: "view", id: saved.id });
              await refresh();
            }}
          />
        )}
      </section>
      {importing && <ImportDialog onClose={() => setImporting(false)} onImported={refresh} />}
      {showSettings && <SettingsDialog onClose={() => setShowSettings(false)} />}
      {pairing && <PairingDialog key={pairing.clientId} request={pairing} onDone={() => setPairing(null)} />}
    </div>
  );
}

function TrashPane({ item, onRestored }: { item: ItemSummary | undefined; onRestored: () => void }) {
  return item ? <TrashItem item={item} onRestored={onRestored} /> : <p className="empty">Select an item</p>;
}
