import assert from "node:assert/strict";
import { afterEach, test } from "node:test";

import { SentinelApiClient } from "../api/client.js";
import { readApiKey } from "../auth/keychain.js";
import type { SentinelConfig } from "../config/sentinel.config.js";

const config: SentinelConfig = {
  apiUrl: "http://sentinel.test",
  repoName: "repo",
  provider: "local",
  model: "ollama",
  variants: {}
};

const originalFetch = globalThis.fetch;

afterEach(() => {
  delete process.env.SENTINEL_API_TOKEN;
  globalThis.fetch = originalFetch;
});

test("readApiKey prefers SENTINEL_API_TOKEN", async () => {
  process.env.SENTINEL_API_TOKEN = "env-token";
  assert.equal(await readApiKey(config), "env-token");
});

test("api client sends bearer token from auth helper", async () => {
  process.env.SENTINEL_API_TOKEN = "env-token";
  let authorization: string | undefined;
  globalThis.fetch = async (_input: string | URL | Request, init?: RequestInit) => {
    authorization = (init?.headers as Record<string, string> | undefined)?.Authorization;
    return new Response("[]", { status: 200, headers: { "Content-Type": "application/json" } });
  };

  await new SentinelApiClient(config).findings();

  assert.equal(authorization, "Bearer env-token");
});
