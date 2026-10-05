import { useEffect, useState, type KeyboardEvent } from "react";
import { api, errorMessage, type ItemSummary, type QuickCopy } from "../api";
import { IconSearch } from "./icons";

const MAX_RESULTS = 50;

/** Search box and results of the ⌘⇧Space window. Copying closes the window via `onDone`. */
export function QuickSearch({ onDone }: { onDone: () => void }) {
  const [query, setQuery] = useState("");
  const [items, setItems] = useState<ItemSummary[]>([]);
  const [index, setIndex] = useState(0);
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    api
      .items({ query })
      .then((list) => {
        if (!live) return;
        setItems(list.filter((i) => !i.damaged).slice(0, MAX_RESULTS));
        setIndex(0);
      })
      .catch((e) => live && setMessage(errorMessage(e)));
    return () => {
      live = false;
    };
  }, [query]);

  async function copy(what: QuickCopy, item = items[index]) {
    if (!item) return;
    setMessage(null);
    try {
      await api.quickCopy(item.id, what);
      onDone();
    } catch (e) {
      setMessage(errorMessage(e));
    }
  }

  function onKeyDown(e: KeyboardEvent<HTMLInputElement>) {
    const input = e.currentTarget;
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setIndex((i) => Math.min(i + 1, items.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setIndex((i) => Math.max(i - 1, 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      void copy(e.metaKey ? "username" : "password");
    } else if (e.metaKey && e.key.toLowerCase() === "c" && input.selectionStart === input.selectionEnd) {
      // ⌘C with no text selected copies the one-time code instead of nothing.
      e.preventDefault();
      if (items[index]?.hasTotp) void copy("totp");
      else setMessage("This item has no one-time password");
    }
  }

  return (
    <div className="quick-search">
      <div className="search">
        <IconSearch />
        <input
          autoFocus
          aria-label="Quick search"
          placeholder="Search Keyorra"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={onKeyDown}
        />
      </div>
      {items.length === 0 ? (
        <p className="empty">{query ? "Nothing matches your search" : "No items yet"}</p>
      ) : (
        <ul role="listbox" aria-label="Results">
          {items.map((item, i) => (
            <li
              key={item.id}
              role="option"
              aria-selected={i === index}
              onMouseEnter={() => setIndex(i)}
              onClick={() => void copy("password", item)}
            >
              <span className="title">{item.title || "Untitled"}</span>
              <span className="subtitle">{item.subtitle}</span>
              {item.hasTotp && <span className="badge">2FA</span>}
            </li>
          ))}
        </ul>
      )}
      {message && (
        <p className="error" role="alert">
          {message}
        </p>
      )}
      <footer className="hints">↵ copy password · ⌘↵ copy username · ⌘C copy one-time code · esc close</footer>
    </div>
  );
}
