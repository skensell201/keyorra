// A generated password the user chose on this page and that Lockbox already saved as a draft login.
// Kept in the content script's memory only, per page.

export interface Draft {
  id: string;
  username: string;
  password: string;
}

/** The same generated password is never saved twice. */
export function alreadyDrafted(draft: Draft | null, password: string): boolean {
  return draft !== null && draft.password === password;
}

export type OfferPlan = { kind: "none" } | { kind: "update"; itemId: string } | { kind: "lookup" };

/** What to do when the user submits `s`: the draft already holds it, only needs the username, or is unrelated. */
export function planOffer(draft: Draft | null, s: { username: string; password: string }): OfferPlan {
  if (!draft || draft.password !== s.password) return { kind: "lookup" };
  const same = draft.username.trim().toLowerCase() === s.username.trim().toLowerCase();
  if (same) return { kind: "none" };
  // Saved before the username was typed: offer to complete that very login, never another one.
  if (draft.username === "") return { kind: "update", itemId: draft.id };
  return { kind: "lookup" };
}
