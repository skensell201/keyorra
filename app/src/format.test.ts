import { expect, test } from "vitest";
import { fieldText, formatCode, plural } from "./format";

test("field values as text", () => {
  expect(fieldText({ type: "text", value: "ivan" })).toBe("ivan");
  expect(fieldText({ type: "month_year", value: 202712 })).toBe("12/2027");
  expect(fieldText({ type: "date", value: 631152000 })).toBe("1990-01-01");
});

test("one-time codes are grouped", () => {
  expect(formatCode("123456")).toBe("123 456");
  expect(formatCode("12345678")).toBe("1234 5678");
  expect(formatCode("1234567")).toBe("1234567");
});

test("an out-of-range date falls back to the raw number", () => {
  expect(fieldText({ type: "date", value: 1e20 })).toBe("100000000000000000000");
});

test("counts take the right number", () => {
  expect(plural(1, "change")).toBe("1 change");
  expect(plural(0, "change")).toBe("0 changes");
  expect(plural(3, "copy", "copies")).toBe("3 copies");
});
