import { useEffect, useState } from "react";
import { api, CLIPBOARD_CLEAR_SECS, errorMessage, type Field, type Item, type TotpCode } from "../api";
import { fieldText, formatCode, KIND_LABEL } from "../format";

interface Props {
  itemId: string;
  onEdit: (item: Item) => void;
  onDeleted: () => void;
}

/** Must be rendered with `key={itemId}`: state is per item, and field ids like "password" repeat across items. */
export function ItemDetail({ itemId, onEdit, onDeleted }: Props) {
  const [item, setItem] = useState<Item | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [revealed, setRevealed] = useState<Set<string>>(new Set());
  const [copied, setCopied] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);

  useEffect(() => {
    let live = true;
    api
      .item(itemId)
      .then((loaded) => live && setItem(loaded))
      .catch((e) => live && setError(errorMessage(e)));
    return () => {
      live = false;
    };
  }, [itemId]);

  useEffect(() => {
    if (!copied) return;
    const timer = setTimeout(() => setCopied(false), 3000);
    return () => clearTimeout(timer);
  }, [copied]);

  if (error) {
    return (
      <div className="banner error" role="alert">
        {error}
      </div>
    );
  }
  if (!item) return null;

  async function copy(fieldId: string) {
    try {
      await api.copyField(itemId, fieldId);
      setCopied(true);
    } catch (e) {
      setActionError(errorMessage(e));
    }
  }

  async function remove() {
    try {
      await api.deleteItem(itemId);
      onDeleted();
    } catch (e) {
      setActionError(errorMessage(e));
    }
  }

  function toggle(fieldId: string) {
    setRevealed((current) => {
      const next = new Set(current);
      if (next.has(fieldId)) next.delete(fieldId);
      else next.add(fieldId);
      return next;
    });
  }

  const groups = [{ id: "__main", title: "", fields: item.fields }, ...item.sections].filter((g) => g.fields.length > 0);

  return (
    <article className="item-detail">
      {actionError && (
        <div className="banner error" role="alert">
          {actionError}
          <button onClick={() => setActionError(null)}>Dismiss</button>
        </div>
      )}
      <header>
        <div>
          <span className="kind">{KIND_LABEL[item.kind]}</span>
          <h2>{item.title}</h2>
        </div>
        <div className="actions">
          <button onClick={() => onEdit(item)}>Edit</button>
          {confirmDelete ? (
            <>
              <button className="danger" onClick={remove}>
                Move to trash
              </button>
              <button onClick={() => setConfirmDelete(false)}>Cancel</button>
            </>
          ) : (
            <button onClick={() => setConfirmDelete(true)}>Delete</button>
          )}
        </div>
      </header>
      {item.urls.length > 0 && (
        <div className="urls">
          {item.urls.map((url) => (
            <span key={url}>{url}</span>
          ))}
        </div>
      )}
      {groups.map((group) => (
        <section key={group.id} className="field-group">
          {group.title && <h3>{group.title}</h3>}
          {group.fields.map((field) =>
            field.value.type === "totp" ? (
              <TotpRow key={field.id} itemId={itemId} label={field.label} onCopy={() => copy("totp")} />
            ) : (
              <FieldRow
                key={field.id}
                field={field}
                revealed={revealed.has(field.id)}
                onToggle={() => toggle(field.id)}
                onCopy={() => copy(field.id)}
              />
            ),
          )}
        </section>
      ))}
      {item.notes && (
        <section className="field-group">
          <h3>Notes</h3>
          <div className="field notes">{item.notes}</div>
        </section>
      )}
      {item.tags.length > 0 && <p className="muted">Tags: {item.tags.join(", ")}</p>}
      {item.attachments.length > 0 && (
        <p className="muted">Attachments: {item.attachments.map((a) => a.name).join(", ")}</p>
      )}
      {item.password_history.length > 0 && (
        <p className="muted">Password changed {item.password_history.length} time(s)</p>
      )}
      {copied && (
        <div className="toast" role="status">
          Copied. The clipboard clears in {CLIPBOARD_CLEAR_SECS} seconds.
        </div>
      )}
    </article>
  );
}

function FieldRow(props: { field: Field; revealed: boolean; onToggle: () => void; onCopy: () => void }) {
  const { field, revealed, onToggle, onCopy } = props;
  const text = fieldText(field.value);
  if (!text) return null;
  const concealed = field.value.type === "concealed";
  return (
    <div className="field">
      <span className="label">{field.label}</span>
      <span className={concealed ? "value mono" : "value"}>{concealed && !revealed ? "••••••••••" : text}</span>
      <span className="field-actions">
        {concealed && (
          <button aria-label={`${revealed ? "Hide" : "Reveal"} ${field.label}`} onClick={onToggle}>
            {revealed ? "Hide" : "Reveal"}
          </button>
        )}
        <button aria-label={`Copy ${field.label}`} onClick={onCopy}>
          Copy
        </button>
      </span>
    </div>
  );
}

function TotpRow({ itemId, label, onCopy }: { itemId: string; label: string; onCopy: () => void }) {
  const [code, setCode] = useState<TotpCode | null>(null);
  const [failed, setFailed] = useState(false);
  const name = label || "one-time password";

  useEffect(() => {
    let live = true;
    const load = () =>
      api
        .totp(itemId)
        .then((c) => live && setCode(c))
        .catch(() => {
          if (!live) return;
          setFailed(true);
          clearInterval(timer);
        });
    const timer = setInterval(load, 1000);
    load();
    return () => {
      live = false;
      clearInterval(timer);
    };
  }, [itemId]);

  if (failed) {
    return (
      <div className="field">
        <span className="label">{name}</span>
        <span className="value error">Invalid one-time password</span>
      </div>
    );
  }
  if (!code) return null;
  return (
    <div className="field">
      <span className="label">{name}</span>
      <span className="value mono">
        {formatCode(code.code)} <span className="muted">{code.secondsLeft}s</span>
      </span>
      <span className="field-actions">
        <button aria-label={`Copy ${name}`} onClick={onCopy}>
          Copy
        </button>
      </span>
    </div>
  );
}
