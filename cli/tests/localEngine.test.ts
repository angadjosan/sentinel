import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";

import { ConfigSchema } from "../src/config/sentinel.config.js";
import { runLocalSourceScan } from "../src/engine/localEngine.js";

// End-to-end: this actually spawns the local Python engine (worker/sentinel_worker/local_cli.py)
// against a real temp git repo, proving the Node <-> Python wiring — argv, stdin diff piping,
// and the stdout JSON contract — all work together, not just each side in isolation.

const SECRET_DIFF = `diff --git a/config.py b/config.py
--- a/config.py
+++ b/config.py
@@ -1,1 +1,2 @@
 import os
+AWS_ACCESS_KEY_ID = "AKIA1234567890ABCDEF"
`;

// The spawned Python engine writes its local trace to $HOME/.sentinel/runs —
// point HOME at a throwaway dir for the duration of each test so these don't
// write into the real developer's home directory.
async function withIsolatedHome<T>(fn: () => Promise<T>): Promise<T> {
  const originalHome = process.env.HOME;
  process.env.HOME = mkdtempSync(join(tmpdir(), "sentinel-cli-home-"));
  try {
    return await fn();
  } finally {
    process.env.HOME = originalHome;
  }
}

test("runLocalSourceScan finds a secret via the real local Python engine", async () => {
  const repoDir = mkdtempSync(join(tmpdir(), "sentinel-cli-e2e-"));
  execFileSync("git", ["init", "-q"], { cwd: repoDir });
  writeFileSync(join(repoDir, "config.py"), "import os\n");

  const config = ConfigSchema.parse({ repoName: "e2e-repo", provider: "mock", model: "mock" });

  const { result, exitCode } = await withIsolatedHome(() =>
    runLocalSourceScan({ config, repoDir, diff: SECRET_DIFF, runContext: "local" })
  );

  assert.equal(result.finding_count, 1);
  assert.equal(result.findings[0].vuln_type, "secret_leak");
  assert.equal(exitCode, 1);
});

test("runLocalSourceScan exits 0 on a clean diff", async () => {
  const repoDir = mkdtempSync(join(tmpdir(), "sentinel-cli-e2e-clean-"));
  execFileSync("git", ["init", "-q"], { cwd: repoDir });

  const config = ConfigSchema.parse({ repoName: "e2e-repo-clean", provider: "mock", model: "mock" });

  const cleanDiff = `diff --git a/readme.md b/readme.md\n--- a/readme.md\n+++ b/readme.md\n@@ -1 +1,2 @@\n hello\n+world\n`;
  const { result, exitCode } = await withIsolatedHome(() =>
    runLocalSourceScan({ config, repoDir, diff: cleanDiff, runContext: "local" })
  );

  assert.equal(result.finding_count, 0);
  assert.equal(exitCode, 0);
});
