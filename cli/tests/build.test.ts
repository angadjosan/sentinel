import { test } from "node:test";
import assert from "node:assert/strict";
import { BUILD_TARGETS } from "../src/build-targets.js";

test("build targets cover mac + linux on both arches", () => {
  const triples = BUILD_TARGETS.map((t: { bunTarget: string }) => t.bunTarget);
  assert.deepEqual(new Set(triples), new Set([
    "bun-darwin-arm64",
    "bun-darwin-x64",
    "bun-linux-x64",
    "bun-linux-arm64",
  ]));
});
