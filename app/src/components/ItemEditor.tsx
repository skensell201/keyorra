import { useState, type FormEvent } from "react";
import { api, errorMessage, type FieldValue, type Item } from "../api";
import { KIND_LABEL } from "../format";
import { Generator } from "./Generator";

interface Props {
  item: Item;
  onSave: (saved: Item) => void;
  onCancel: () => void;
}

/** Edits the common fields; other fields and sections are passed through unchanged. */
export function ItemEditor({ item, onSave, onCancel }: Props) {
  const [draft, setDraft] = useState<Item>(item);
  const [urls, setUrls] = useState(item.urls.join("\n"));
  const [tags, setTags] = useState(item.tags.join(", "));
  const [showPassword, setShowPassword] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const usernameIndex = draft.fields.findIndex((f) => f.purpose === "username");
  const passwordIndex = draft.fields.findIndex((f) => f.purpose === "password");
  const text = (index: number) => {
    const value = draft.fields[index]?.value;
    return value && typeof value.value === "string" ? value.value : "";
  };
  const setField = (index: number, value: string) =>
    setDraft((d) => ({
      ...d,
      fields: d.fields.map((f, i) => (i === index ? { ...f, value: { type: f.value.type, value } as FieldValue } : f)),
    }));

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const saved = await api.saveItem({
        ...draft,
        urls: urls.split("\n").map((u) => u.trim()).filter(Boolean),
        tags: tags.split(",").map((t) => t.trim()).filter(Boolean),
      });
      onSave(saved);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="editor" onSubmit={submit}>
      <header>
        <div>
          <span className="kind">{KIND_LABEL[draft.kind]}</span>
          <h2>{item.title ? "Edit item" : "New item"}</h2>
        </div>
        <div className="actions">
          <button type="button" onClick={onCancel}>
            Cancel
          </button>
          <button type="submit" className="primary" disabled={busy}>
            Save
          </button>
        </div>
      </header>
      {error && (
        <div className="banner error" role="alert">
          {error}
        </div>
      )}
      <label>
        Title
        <input autoFocus value={draft.title} onChange={(e) => setDraft({ ...draft, title: e.target.value })} />
      </label>
      {usernameIndex >= 0 && (
        <label>
          Username
          <input value={text(usernameIndex)} onChange={(e) => setField(usernameIndex, e.target.value)} />
        </label>
      )}
      {passwordIndex >= 0 && (
        <>
          <div className="row">
            <label>
              Password
              <input
                className="mono"
                type={showPassword ? "text" : "password"}
                value={text(passwordIndex)}
                onChange={(e) => setField(passwordIndex, e.target.value)}
              />
            </label>
            <button type="button" onClick={() => setShowPassword((s) => !s)}>
              {showPassword ? "Hide" : "Show"}
            </button>
            <button type="button" onClick={() => setGenerating((g) => !g)}>
              Generate
            </button>
          </div>
          {generating && (
            <Generator
              onUse={(value) => {
                setField(passwordIndex, value);
                setGenerating(false);
              }}
            />
          )}
        </>
      )}
      {draft.kind === "login" && (
        <label>
          Websites
          <textarea rows={2} value={urls} onChange={(e) => setUrls(e.target.value)} />
        </label>
      )}
      <label>
        Notes
        <textarea rows={4} value={draft.notes} onChange={(e) => setDraft({ ...draft, notes: e.target.value })} />
      </label>
      <label>
        Tags
        <input value={tags} onChange={(e) => setTags(e.target.value)} />
      </label>
      <label className="check">
        <input type="checkbox" checked={draft.favorite} onChange={(e) => setDraft({ ...draft, favorite: e.target.checked })} />
        Favorite
      </label>
      {draft.sections.length > 0 && <p className="muted">Other fields are kept as they are.</p>}
    </form>
  );
}
