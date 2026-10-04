import { afterEach, beforeEach, expect, test, vi, type Mock } from "vitest";
import { watchSubmissions, type Submission } from "./capture";

let onSubmit: Mock<(s: Submission) => void>;
let stop: () => void;
let trusted = true;

function setup(html: string) {
  document.body.innerHTML = html;
  stop?.();
  onSubmit = vi.fn<(s: Submission) => void>();
  stop = watchSubmissions(document, onSubmit, { trusted: () => trusted });
}

beforeEach(() => {
  vi.useFakeTimers();
  trusted = true;
});

afterEach(() => {
  stop?.();
  vi.useRealTimers();
});

const LOGIN = `<form id="f"><input id="u" type="email" autocomplete="username"><input id="p" type="password" autocomplete="current-password"><button id="b" type="submit">Go</button></form>`;
const fill = (id: string, v: string) => ((document.getElementById(id) as HTMLInputElement).value = v);
const submit = () => document.getElementById("f")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));

test("a submitted form with a filled password is reported", () => {
  setup(LOGIN);
  fill("u", "ivan@x.com");
  fill("p", "hunter2");
  submit();
  expect(onSubmit).toHaveBeenCalledWith({ username: "ivan@x.com", password: "hunter2" });
});

test("an empty password is not reported", () => {
  setup(LOGIN);
  fill("u", "ivan@x.com");
  submit();
  expect(onSubmit).not.toHaveBeenCalled();
});

test("clicking a submit button reports; a plain button outside any form does not", () => {
  setup(LOGIN + `<button id="x">Sign in</button>`);
  fill("u", "a");
  fill("p", "b");
  document.getElementById("b")!.dispatchEvent(new MouseEvent("click", { bubbles: true }));
  expect(onSubmit).toHaveBeenCalledTimes(1);
  vi.advanceTimersByTime(3000);
  document.getElementById("x")!.dispatchEvent(new MouseEvent("click", { bubbles: true }));
  expect(onSubmit).toHaveBeenCalledTimes(1);
});

test("a type=button with sign-in text inside the form counts; other text does not", () => {
  setup(`<form id="f"><input id="u"><input id="p" type="password"><button type="button" id="a">Cancel</button><button type="button" id="b">Войти</button></form>`);
  fill("u", "a");
  fill("p", "b");
  document.getElementById("a")!.dispatchEvent(new MouseEvent("click", { bubbles: true }));
  expect(onSubmit).not.toHaveBeenCalled();
  document.getElementById("b")!.dispatchEvent(new MouseEvent("click", { bubbles: true }));
  expect(onSubmit).toHaveBeenCalledTimes(1);
});

test("Enter in the password field reports; other keys do not", () => {
  setup(LOGIN);
  fill("u", "a");
  fill("p", "b");
  const p = document.getElementById("p")!;
  p.dispatchEvent(new KeyboardEvent("keydown", { key: "a", bubbles: true }));
  expect(onSubmit).not.toHaveBeenCalled();
  p.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
  expect(onSubmit).toHaveBeenCalledWith({ username: "a", password: "b" });
});

test("sign-up and change forms report the new password", () => {
  setup(`<form id="f"><input id="u" type="email"><input id="p" type="password" autocomplete="new-password"><input id="c" type="password" autocomplete="new-password"></form>`);
  fill("u", "me@x.com");
  fill("p", "new-secret");
  fill("c", "new-secret");
  submit();
  expect(onSubmit).toHaveBeenCalledWith({ username: "me@x.com", password: "new-secret" });

  vi.advanceTimersByTime(3000);
  setup(`<form id="f"><input id="o" type="password"><input id="n" type="password"><input id="c" type="password"></form>`);
  fill("o", "old");
  fill("n", "fresh");
  fill("c", "fresh");
  submit();
  expect(onSubmit).toHaveBeenCalledWith({ username: "", password: "fresh", changePassword: true });
});

test("a sign-up form with two unmarked password fields is not a change-password form", () => {
  setup(`<form id="f"><input id="u" type="email"><input id="p" type="password"><input id="c" type="password"></form>`);
  fill("u", "me@x.com");
  fill("p", "secret");
  fill("c", "secret");
  submit();
  expect(onSubmit).toHaveBeenCalledWith({ username: "me@x.com", password: "secret" });
});

test("sign-up style button texts count as submit buttons", () => {
  for (const label of ["Sign up", "Register", "Create account", "Save", "Update", "Change password", "Зарегистрироваться", "Сохранить"]) {
    vi.advanceTimersByTime(3000);
    setup(`<form id="f"><input id="u" type="email"><input id="p" type="password"><button id="b" type="button">${label}</button></form>`);
    fill("u", "a");
    fill("p", "b");
    document.getElementById("b")!.dispatchEvent(new MouseEvent("click", { bubbles: true }));
    expect(onSubmit, label).toHaveBeenCalledTimes(1);
  }
});

test("duplicates within 2 s are reported once, later ones again", () => {
  setup(LOGIN);
  fill("u", "a");
  fill("p", "b");
  document.getElementById("b")!.dispatchEvent(new MouseEvent("click", { bubbles: true }));
  submit();
  document.getElementById("p")!.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
  expect(onSubmit).toHaveBeenCalledTimes(1);
  vi.advanceTimersByTime(2100);
  submit();
  expect(onSubmit).toHaveBeenCalledTimes(2);
});

test("untrusted events are ignored", () => {
  setup(LOGIN);
  fill("u", "a");
  fill("p", "b");
  trusted = false;
  submit();
  document.getElementById("b")!.dispatchEvent(new MouseEvent("click", { bubbles: true }));
  document.getElementById("p")!.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
  expect(onSubmit).not.toHaveBeenCalled();
});

test("the real isTrusted flag is the default: script-made events do nothing", () => {
  document.body.innerHTML = LOGIN;
  const fn = vi.fn();
  const off = watchSubmissions(document, fn);
  fill("p", "b");
  submit();
  off();
  expect(fn).not.toHaveBeenCalled();
});
