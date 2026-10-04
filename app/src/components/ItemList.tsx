import { useState } from "react";
import type { ItemKind, ItemSummary } from "../api";
import { KIND_LABEL, NEW_KINDS } from "../format";
import { IconPlus, IconSearch, KindIcon } from "./icons";

interface Props {
  items: ItemSummary[];
  query: string;
  onQuery: (query: string) => void;
  selectedId: string | null;
  onSelect: (id: string) => void;
  onNew: (kind: ItemKind) => void;
  canCreate: boolean;
}

export function ItemList({ items, query, onQuery, selectedId, onSelect, onNew, canCreate }: Props) {
  const [menu, setMenu] = useState(false);
  return (
    <section className="list" aria-label="Items">
      <div className="toolbar">
        <div className="search">
          <IconSearch />
          <input type="search" placeholder="Search" aria-label="Search" value={query} onChange={(e) => onQuery(e.target.value)} />
        </div>
        <button
          aria-label="+ New"
          aria-haspopup="menu"
          aria-expanded={menu}
          disabled={!canCreate}
          onClick={() => setMenu((m) => !m)}
        >
          <IconPlus />
          New
        </button>
        {menu && (
          <div className="menu" role="menu">
            {NEW_KINDS.map((kind) => (
              <button
                key={kind}
                role="menuitem"
                onClick={() => {
                  setMenu(false);
                  onNew(kind);
                }}
              >
                <KindIcon kind={kind} />
                {KIND_LABEL[kind]}
              </button>
            ))}
          </div>
        )}
      </div>
      {items.length === 0 ? (
        <p className="empty">{query ? "Nothing matches your search" : "No items yet"}</p>
      ) : (
        <ul>
          {items.map((item) => (
            <li key={item.id}>
              <button aria-current={item.id === selectedId} onClick={() => onSelect(item.id)}>
                <span className="monogram" aria-hidden="true">
                  {monogram(item.title)}
                </span>
                <span className="text">
                  <span className={item.damaged ? "damaged" : undefined}>
                    {item.favorite ? "★ " : ""}
                    {item.title || "Untitled"}
                  </span>
                  {item.subtitle && <span className="subtitle">{item.subtitle}</span>}
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

/** First letter or digit of the title, for the item's tile. */
function monogram(title: string): string {
  const match = title.match(/[\p{L}\p{N}]/u);
  return match ? match[0] : "•";
}
