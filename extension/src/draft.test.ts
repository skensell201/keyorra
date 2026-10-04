import { expect, test } from "vitest";
import { alreadyDrafted, planOffer } from "./draft";

const draft = { id: "d1", username: "me@x.com", password: "gen-pw" };

test("the same generated password is not drafted twice", () => {
  expect(alreadyDrafted(null, "gen-pw")).toBe(false);
  expect(alreadyDrafted(draft, "gen-pw")).toBe(true);
  expect(alreadyDrafted(draft, "other")).toBe(false);
});

test("submitting what the draft already holds shows no bar", () => {
  expect(planOffer(draft, { username: "ME@x.com", password: "gen-pw" })).toEqual({ kind: "none" });
});

test("a draft saved before the username was typed is offered as an update of that draft", () => {
  expect(planOffer({ ...draft, username: "" }, { username: "me@x.com", password: "gen-pw" })).toEqual({ kind: "update", itemId: "d1" });
});

test("unrelated submissions go through the normal lookup", () => {
  expect(planOffer(null, { username: "me@x.com", password: "gen-pw" })).toEqual({ kind: "lookup" });
  expect(planOffer(draft, { username: "me@x.com", password: "typed-by-hand" })).toEqual({ kind: "lookup" });
  expect(planOffer(draft, { username: "someone@else", password: "gen-pw" })).toEqual({ kind: "lookup" });
});
