// Notices when the user submits a login or sign-up form. Only real user events count (isTrusted).
import { findLoginFields, findNewPasswordFields } from "./detect";

export interface Submission {
  username: string;
  password: string;
  /** The form asks for the current password and sets a new one: it names no account of its own. */
  changePassword?: boolean;
}

export interface CaptureOptions {
  /** Whether an event comes from the user. Defaults to `isTrusted`. */
  trusted?: (e: Event) => boolean;
}

const SUBMIT_TEXT = /sign.?in|sign.?up|register|create|save|update|change|log.?in|continue|next|войти|далее|зарегистр|сохран/i;
const DEDUP_MS = 2000;

/** The credentials in a form (or the page if there is no form); the new password wins on sign-up/change forms. */
function read(scope: Document | HTMLElement): Submission | null {
  const fields = findLoginFields(scope);
  const news = findNewPasswordFields(scope);
  const fresh = news.find((p) => p.value);
  const password = fresh?.value || fields.password?.value || "";
  if (!password) return null;
  const change = !!fresh && !!fields.password && !news.includes(fields.password);
  return { username: fields.username?.value ?? "", password, ...(change ? { changePassword: true } : {}) };
}

function submitLike(el: HTMLElement): boolean {
  if (el instanceof HTMLButtonElement) return el.type === "submit" || SUBMIT_TEXT.test(el.textContent ?? "");
  if (el instanceof HTMLInputElement) return el.type === "submit" || (el.type === "button" && SUBMIT_TEXT.test(el.value));
  return false;
}

export function watchSubmissions(doc: Document, onSubmit: (s: Submission) => void, options: CaptureOptions = {}): () => void {
  const trusted = options.trusted ?? ((e: Event) => e.isTrusted);
  let last: { key: string; at: number } | null = null;

  const report = (scope: Document | HTMLElement) => {
    const s = read(scope);
    if (!s) return;
    const key = `${s.username}\0${s.password}`;
    const at = Date.now();
    if (last && last.key === key && at - last.at < DEDUP_MS) return;
    last = { key, at };
    onSubmit(s);
  };

  const onFormSubmit = (e: Event) => {
    if (!trusted(e) || !(e.target instanceof HTMLFormElement)) return;
    report(e.target);
  };
  const onClick = (e: Event) => {
    if (!trusted(e) || !(e.target instanceof Element)) return;
    const el = e.target.closest<HTMLElement>("button, input");
    if (!el || !submitLike(el)) return;
    const form = (el as HTMLButtonElement).form ?? el.closest("form");
    if (form) report(form);
  };
  const onKey = (e: Event) => {
    const k = e as KeyboardEvent;
    if (k.key !== "Enter" || !trusted(e)) return;
    const t = e.target;
    if (!(t instanceof HTMLInputElement) || t.type !== "password") return;
    report(t.form ?? doc);
  };

  doc.addEventListener("submit", onFormSubmit, true);
  doc.addEventListener("click", onClick, true);
  doc.addEventListener("keydown", onKey, true);
  return () => {
    doc.removeEventListener("submit", onFormSubmit, true);
    doc.removeEventListener("click", onClick, true);
    doc.removeEventListener("keydown", onKey, true);
  };
}
