import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const INSTALL_SH = resolve(__dirname, "../../../install.sh");

test("install.sh resolves the darwin-arm64 asset in dry-run", () => {
  const out = execFileSync("bash", [INSTALL_SH], {
    env: { ...process.env, SENTINEL_NO_DOWNLOAD: "1", SENTINEL_FAKE_UNAME: "Darwin arm64" },
    encoding: "utf8",
  });
  assert.match(out, /sentinel-darwin-arm64/);
});

test("install.sh resolves the linux-x64 asset in dry-run", () => {
  const out = execFileSync("bash", [INSTALL_SH], {
    env: { ...process.env, SENTINEL_NO_DOWNLOAD: "1", SENTINEL_FAKE_UNAME: "Linux x86_64" },
    encoding: "utf8",
  });
  assert.match(out, /sentinel-linux-x64/);
});
