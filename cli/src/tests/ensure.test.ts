import { test } from "node:test";
import assert from "node:assert/strict";
import { workerDockerArgs } from "../backend/ensure.js";

test("workerDockerArgs wires Neon + LLM env into the container", () => {
  const argv = workerDockerArgs({
    image: "ghcr.io/angadjosan/sentinel-worker:latest",
    databaseUrl: "postgresql+asyncpg://u:p@ep.neon.tech/db",
    accountId: "acct_123",
    anthropicKey: "sk-ant-xxx",
  });
  assert.ok(argv.includes("--rm"));
  assert.ok(argv.includes("ghcr.io/angadjosan/sentinel-worker:latest"));
  assert.ok(argv.some((a: string) => a.startsWith("DATABASE_URL=")));
  assert.ok(argv.some((a: string) => a === "SENTINEL_ACCOUNT_ID=acct_123"));
  assert.ok(argv.some((a: string) => a === "ANTHROPIC_API_KEY=sk-ant-xxx"));
});
