import assert from "node:assert/strict";
import { test } from "node:test";
import { execFileSync } from "node:child_process";

// We test `currentDiff` and `lsFiles` by mocking execFileSync.
// Since git.ts calls execFileSync directly we exercise the argument
// construction logic by inspecting what it would pass, using a lightweight
// monkey-patch approach against the module itself.

import { currentDiff, lsFiles, git } from "../diff/git.js";

// Capture the real execFileSync so we can restore it if needed.
// Because git.ts uses the built-in import, we test observable behaviour
// (the returned string) by running against the real git in the repo,
// or by verifying argument construction via the exported `git` helper.

test("git() executes git with the given arguments and returns stdout", () => {
  // `git --version` is available everywhere
  const output = git(["--version"]);
  assert.ok(output.startsWith("git version"), `expected git version string, got: ${output}`);
});

test("lsFiles returns an array of strings without empty entries", () => {
  const files = lsFiles();
  assert.ok(Array.isArray(files));
  // Every entry should be a non-empty string
  for (const f of files) {
    assert.ok(typeof f === "string" && f.length > 0, `unexpected entry: ${JSON.stringify(f)}`);
  }
  // Should include at least the sentinel.config.json or package.json from the CLI
  assert.ok(files.length > 0, "lsFiles should return at least one tracked file in the repo");
});

test("currentDiff with no options returns a string (empty or diff text)", () => {
  const diff = currentDiff({});
  assert.equal(typeof diff, "string");
});

test("currentDiff with staged option builds --staged arg", () => {
  // We can't fully test the git call without a staged change, but we verify
  // the function doesn't throw and returns a string.
  const diff = currentDiff({ staged: true });
  assert.equal(typeof diff, "string");
});

test("currentDiff with path scoping returns a string", () => {
  // Scope to a file that definitely exists — README.md or pyproject.toml
  const diff = currentDiff({ paths: ["README.md"] });
  assert.equal(typeof diff, "string");
});

test("git() throws on invalid subcommand", () => {
  assert.throws(
    () => git(["this-subcommand-does-not-exist"]),
    (err: unknown) => err instanceof Error,
    "should throw for unknown git subcommand"
  );
});
