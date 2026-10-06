import { useCallback, useEffect, useRef, useState } from "react";
import {
  api,
  errorMessage,
  type Item,
  type ItemKind,
  type ItemSummary,
  type PairingRequest,
  type Vault,
  type WatchtowerReport,
} from "../api";
import { ConfirmDialog } from "./ConfirmDialog";
import { ImportDialog } from "./ImportDialog";
import { ItemDetail } from "./ItemDetail";
import { ItemEditor } from "./ItemEditor";
import { PairingDialog } from "./PairingDialog";
import { ItemList } from "./ItemList";
import { TrashItem } from "./TrashItem";
import { SettingsDialog } from "./SettingsDialog";
import { SyncBanner } from "./SyncBanner";
import { SyncDialog } from "./SyncDialog";
import { Sidebar, type Selection } from "./Sidebar";
import { Watchtower } from "./Watchtower";

type Pane = { mode: "empty" } | { mode: "view"; id: string } | { mode: "edit"; item: Item; isNew: boolean };

export function Main({ onLock }: { onLock: () => void }) {
  const [vaults, setVaults] = useState<Vault[]>([]);
  const [selection, setSelection] = useState<Selection>({ kind: "all" });
  const [query, setQuery] = useState("");
  const [items, setItems] = useState<ItemSummary[]>([]);
  const [pane, setPane] = useState<Pane>({ mode: "empty" });
  const [importing, setImporting] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [showSync, setShowSync] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pairing, setPairing] = useState<PairingRequest | null>(null);
  const [report, setReport] = useState<WatchtowerReport | null>(null);
  const [flagged, setFlagged] = useState<number | undefined>(undefined);
  const [deletingVault, setDeletingVault] = useState<Vault | null>(null);
  /** Runs once the user agreed to drop unsaved edits. */
  const [pendingLeave, setPendingLeave] = useState<(() => void) | null>(null);
  const editorDirty = useRef(false);
  const onDirtyChange = useCallback((dirty: boolean) => {
    editorDirty.current = dirty;
  }, []);

  useEffect(() => {
    if (pane.mode !== "edit") editorDirty.current = false;
  }, [pane]);

  /** Leaving the editor with unsaved changes asks first. */
  function leaveEditor(action: () => void) {
    if (pane.mode === "edit" && editorDirty.current) setPendingLeave(() => action);
    else action();
  }

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
  const watchtowerOpen = selection.kind === "watchtower";
  const reportSeq = useRef(0);
  /** The full report scores every password, so it is only loaded while Watchtower is open. */
  const loadWatchtower = useCallback(() => {
    const seq = ++reportSeq.current;
    return api
      .watchtower()
      .then((r) => seq === reportSeq.current && setReport(r))
      .catch(() => seq === reportSeq.current && setReport(null));
  }, []);
  const loadCount = useCallback(
    () =>
      api
        .watchtowerCount()
        .then(setFlagged)
        .catch(() => setFlagged(undefined)),
    [],
  );
  const refresh = useCallback(
    () => Promise.all([loadVaults(), loadItems(), loadCount(), watchtowerOpen ? loadWatchtower() : undefined]),
    [loadVaults, loadItems, loadCount, loadWatchtower, watchtowerOpen],
  );

  useEffect(() => {
    const unlisten = api.onPairRequest(setPairing);
    return () => {
      unlisten.then((stop) => stop());
    };
  }, []);
  useEffect(() => {
    // The browser extension saved a login: refresh what's on screen.
    const unlisten = api.onItemsChanged(() => void refresh());
    return () => {
      unlisten.then((stop) => stop());
    };
  }, [refresh]);
  useEffect(() => {
    loadVaults();
    loadCount();
  }, [loadVaults, loadCount]);
  useEffect(() => {
    if (watchtowerOpen) {
      loadWatchtower();
    } else {
      reportSeq.current++;
      setReport(null);
    }
  }, [watchtowerOpen, loadWatchtower]);
  useEffect(() => {
    loadItems();
  }, [loadItems]);

  const targetVault =
    selection.kind === "vault"
      ? selection.id
      : selection.kind === "trash" || selection.kind === "watchtower"
        ? undefined
        : vaults[0]?.id;

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

  async function renameVault(id: string, name: string) {
    try {
      await api.renameVault(id, name);
      await loadVaults();
    } catch (e) {
      setError(errorMessage(e));
    }
  }

  function askDeleteVault(vault: Vault) {
    if (vault.itemCount > 0) {
      const s = vault.itemCount === 1 ? "" : "s";
      setError(`"${vault.name}" still has ${vault.itemCount} item${s}. Delete them first.`);
      return;
    }
    setDeletingVault(vault);
  }

  async function deleteVault(vault: Vault) {
    setDeletingVault(null);
    try {
      await api.deleteVault(vault.id);
      setSelection({ kind: "all" });
      setPane({ mode: "empty" });
      await refresh();
    } catch (e) {
      setError(errorMessage(e));
    }
  }

  return (
    <div className="app">
      <Sidebar
        vaults={vaults}
        selection={selection}
        watchtowerCount={flagged}
        onSelect={(s) =>
          leaveEditor(() => {
            setSelection(s);
            setPane({ mode: "empty" });
          })
        }
        onNewVault={newVault}
        onRenameVault={renameVault}
        onDeleteVault={(v) => leaveEditor(() => askDeleteVault(v))}
        onImport={() => setImporting(true)}
        onLock={() => leaveEditor(onLock)}
        onSettings={() => setShowSettings(true)}
      />
      {selection.kind === "watchtower" ? (
        <Watchtower
          report={report}
          selectedId={pane.mode === "view" ? pane.id : null}
          onOpen={(id) => leaveEditor(() => setPane({ mode: "view", id }))}
          onReport={(r) => {
            setReport(r);
            void loadCount();
          }}
        />
      ) : (
        <ItemList
          items={items}
          query={query}
          onQuery={setQuery}
          selectedId={pane.mode === "view" ? pane.id : null}
          onSelect={(id) => leaveEditor(() => setPane({ mode: "view", id }))}
          onNew={(kind) => leaveEditor(() => void newItem(kind))}
          canCreate={Boolean(targetVault)}
        />
      )}
      <section className="detail">
        <SyncBanner onOpen={() => setShowSync(true)} onSynced={refresh} />
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
            onDirtyChange={onDirtyChange}
            onCancel={() => setPane(pane.isNew ? { mode: "empty" } : { mode: "view", id: pane.item.id })}
            onSave={async (saved) => {
              setPane({ mode: "view", id: saved.id });
              await refresh();
            }}
          />
        )}
      </section>
      {importing && <ImportDialog onClose={() => setImporting(false)} onImported={refresh} />}
      {showSettings && (
        <SettingsDialog
          onClose={() => setShowSettings(false)}
          onOpenSync={() => {
            setShowSettings(false);
            setShowSync(true);
          }}
        />
      )}
      {showSync && <SyncDialog onClose={() => setShowSync(false)} onChanged={() => void refresh()} />}
      {deletingVault && (
        <ConfirmDialog
          title={`Delete vault "${deletingVault.name}"?`}
          confirmLabel="Delete vault"
          danger
          onConfirm={() => deleteVault(deletingVault)}
          onCancel={() => setDeletingVault(null)}
        >
          The vault is empty. Its items in Recently Deleted are removed for good.
        </ConfirmDialog>
      )}
      {pendingLeave && (
        <ConfirmDialog
          title="Discard changes?"
          confirmLabel="Discard"
          danger
          onConfirm={() => {
            const leave = pendingLeave;
            setPendingLeave(null);
            editorDirty.current = false;
            leave();
          }}
          onCancel={() => setPendingLeave(null)}
        >
          Your edits to this item haven't been saved.
        </ConfirmDialog>
      )}
      {pairing && <PairingDialog key={pairing.clientId} request={pairing} onDone={() => setPairing(null)} />}
    </div>
  );
}

function TrashPane({ item, onRestored }: { item: ItemSummary | undefined; onRestored: () => void }) {
  return item ? <TrashItem item={item} onRestored={onRestored} /> : <p className="empty">Select an item</p>;
}
