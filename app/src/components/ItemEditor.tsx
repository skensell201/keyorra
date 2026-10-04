import { useState, type FormEvent } from "react";
import { IconClose } from "./icons";
import { api, errorMessage, type Field, type FieldValue, type Item } from "../api";
import { fieldText, KIND_LABEL } from "../format";
import { Generator } from "./Generator";

interface Props {
  item: Item;
  isNew: boolean;
  onSave: (saved: Item) => void;
  onCancel: () => void;
}

type EditableType = "text" | "concealed" | "totp" | "url" | "email" | "phone";
const EDITABLE_TYPES: EditableType[] = ["text", "concealed", "totp", "url", "email", "phone"];
const TYPE_LABEL: Record<EditableType, string> = {
  text: "Text",
  concealed: "Hidden",
  totp: "One-time password",
  url: "URL",
  email: "Email",
  phone: "Phone",
};

function newFieldId(prefix: string): string {
  return `${prefix}-${Math.random().toString(36).slice(2, 10)}`;
}

/** Edits the common fields and every other field; sections are passed through unchanged. */
export function ItemEditor({ item, isNew, onSave, onCancel }: Props) {
  const [draft, setDraft] = useState<Item>(item);
  const [urls, setUrls] = useState(item.urls.join("\n"));
  const [tags, setTags] = useState(item.tags.join(", "));
  const [showPassword, setShowPassword] = useState(false);
  const [showHidden, setShowHidden] = useState(false);
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
  const custom = draft.fields.map((field, index) => ({ field, index })).filter(({ field }) => !field.purpose);
  const updateField = (index: number, patch: Partial<Field>) =>
    setDraft((d) => ({ ...d, fields: d.fields.map((f, i) => (i === index ? { ...f, ...patch } : f)) }));
  const removeField = (index: number) => setDraft((d) => ({ ...d, fields: d.fields.filter((_, i) => i !== index) }));
  const addField = (type: "text" | "totp") =>
    setDraft((d) => ({
      ...d,
      fields: [
        ...d.fields,
        {
          id: newFieldId(type === "totp" ? "otp" : "field"),
          label: type === "totp" ? "one-time password" : "",
          value: { type, value: "" },
        },
      ],
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
          <h2>{isNew ? "New item" : "Edit item"}</h2>
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
      {custom.length > 0 && (
        <fieldset className="fields">
          <legend>Fields</legend>
          <button type="button" className="reveal" onClick={() => setShowHidden((s) => !s)}>
            {showHidden ? "Hide hidden values" : "Show hidden values"}
          </button>
          {custom.map(({ field, index }, n) => {
            const name = `field ${n + 1}`;
            const editable = field.value.type !== "date" && field.value.type !== "month_year";
            return (
              <div className="field-edit" key={field.id}>
                <input
                  aria-label={`Label of ${name}`}
                  placeholder="Label"
                  value={field.label}
                  onChange={(e) => updateField(index, { label: e.target.value })}
                />
                {editable ? (
                  <input
                    aria-label={`Value of ${name}`}
                    className={field.value.type === "text" ? undefined : "mono"}
                    type={!showHidden && (field.value.type === "concealed" || field.value.type === "totp") ? "password" : "text"}
                    placeholder={field.value.type === "totp" ? "otpauth://… or secret key" : ""}
                    value={text(index)}
                    onChange={(e) => setField(index, e.target.value)}
                  />
                ) : (
                  <span className="muted">{fieldText(field.value)}</span>
                )}
                {editable ? (
                  <select
                    aria-label={`Type of ${name}`}
                    value={field.value.type}
                    onChange={(e) =>
                      updateField(index, {
                        value: { type: e.target.value as EditableType, value: text(index) },
                      })
                    }
                  >
                    {EDITABLE_TYPES.map((t) => (
                      <option key={t} value={t}>
                        {TYPE_LABEL[t]}
                      </option>
                    ))}
                  </select>
                ) : (
                  <span />
                )}
                <button type="button" className="icon" title="Remove" aria-label={`Remove ${name}`} onClick={() => removeField(index)}>
                  <IconClose />
                </button>
              </div>
            );
          })}
        </fieldset>
      )}
      <div className="actions">
        <button type="button" onClick={() => addField("text")}>
          Add field
        </button>
        <button type="button" onClick={() => addField("totp")}>
          Add one-time password
        </button>
      </div>
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
