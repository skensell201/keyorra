import { useCallback, useEffect, useRef, useState } from "react";
import { api, errorMessage, type GeneratorRequest } from "../api";

const DEFAULTS: GeneratorRequest = {
  kind: "password",
  length: 20,
  lowercase: true,
  uppercase: true,
  digits: true,
  symbols: true,
  avoidAmbiguous: false,
  words: 5,
  separator: "-",
  capitalize: false,
  includeNumber: false,
};

type Toggle = "lowercase" | "uppercase" | "digits" | "symbols" | "avoidAmbiguous" | "capitalize" | "includeNumber";

export function Generator({ onUse }: { onUse: (value: string) => void }) {
  const [request, setRequest] = useState<GeneratorRequest>(DEFAULTS);
  const [value, setValue] = useState("");
  const [error, setError] = useState<string | null>(null);

  const latest = useRef(0);

  const regenerate = useCallback(() => {
    const id = ++latest.current;
    api
      .generate(request)
      .then((v) => {
        if (id !== latest.current) return;
        setValue(v);
        setError(null);
      })
      .catch((e) => {
        if (id !== latest.current) return;
        setValue("");
        setError(errorMessage(e));
      });
  }, [request]);

  useEffect(regenerate, [regenerate]);

  const set = (patch: Partial<GeneratorRequest>) => setRequest((r) => ({ ...r, ...patch }));
  const check = (key: Toggle, label: string) => (
    <label className="check">
      <input
        type="checkbox"
        checked={request[key]}
        onChange={(e) => set({ [key]: e.target.checked } as Partial<GeneratorRequest>)}
      />
      {label}
    </label>
  );

  return (
    <div className="generator" role="group" aria-label="Password generator">
      <div className="segmented">
        <button type="button" aria-pressed={request.kind === "password"} onClick={() => set({ kind: "password" })}>
          Password
        </button>
        <button type="button" aria-pressed={request.kind === "passphrase"} onClick={() => set({ kind: "passphrase" })}>
          Passphrase
        </button>
      </div>
      <output className="mono generated">{value}</output>
      {request.kind === "password" ? (
        <>
          <label>
            Length {request.length}
            <input type="range" min={8} max={100} value={request.length} onChange={(e) => set({ length: Number(e.target.value) })} />
          </label>
          <div className="checks">
            {check("lowercase", "a–z")}
            {check("uppercase", "A–Z")}
            {check("digits", "0–9")}
            {check("symbols", "Symbols")}
            {check("avoidAmbiguous", "Avoid look-alikes")}
          </div>
        </>
      ) : (
        <>
          <label>
            Words {request.words}
            <input type="range" min={3} max={10} value={request.words} onChange={(e) => set({ words: Number(e.target.value) })} />
          </label>
          <label>
            Separator
            <input value={request.separator} maxLength={3} onChange={(e) => set({ separator: e.target.value })} />
          </label>
          <div className="checks">
            {check("capitalize", "Capitalize")}
            {check("includeNumber", "Add a number")}
          </div>
        </>
      )}
      {error && <p className="error">{error}</p>}
      <div className="actions">
        <button type="button" onClick={regenerate}>
          Regenerate
        </button>
        <button type="button" disabled={!value} onClick={() => onUse(value)}>
          Use
        </button>
      </div>
    </div>
  );
}
