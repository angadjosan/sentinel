import { test } from "node:test";
import assert from "node:assert/strict";

import { formatAdapterWarnings, printAdapterWarnings } from "../src/output/adapterWarnings.js";

test("formatAdapterWarnings returns null when nothing is unmatched", () => {
  assert.equal(formatAdapterWarnings([]), null);
  assert.equal(formatAdapterWarnings(["", "   "]), null, "blank paths are ignored");
});

test("formatAdapterWarnings lists each unmatched file with singular/plural noun", () => {
  const one = formatAdapterWarnings(["src/routes/weird.py"]);
  assert.ok(one);
  assert.match(one, /1 changed file\b/);
  assert.match(one, /- src\/routes\/weird\.py/);

  const many = formatAdapterWarnings(["a.py", "b.ts"]);
  assert.ok(many);
  assert.match(many, /2 changed files\b/);
  assert.match(many, /- a\.py/);
  assert.match(many, /- b\.ts/);
});

test("formatAdapterWarnings dedupes and trims while preserving order", () => {
  const msg = formatAdapterWarnings(["  a.py ", "b.py", "a.py"]);
  assert.ok(msg);
  const listed = msg.split("\n").filter((l) => l.startsWith("  - "));
  assert.deepEqual(listed, ["  - a.py", "  - b.py"]);
});

test("printAdapterWarnings writes to the sink only when there is a warning", () => {
  let out = "";
  const sink = (s: string) => {
    out += s;
  };

  printAdapterWarnings(undefined, sink);
  printAdapterWarnings([], sink);
  assert.equal(out, "", "no output when nothing is unmatched");

  printAdapterWarnings(["app/legacy.rb"], sink);
  assert.match(out, /warning: no framework adapter matched/);
  assert.match(out, /app\/legacy\.rb/);
  assert.ok(out.endsWith("\n"), "message is newline-terminated");
});
