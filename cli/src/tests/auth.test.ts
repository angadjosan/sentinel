import assert from "node:assert/strict";
import { afterEach, test } from "node:test";

import { SentinelApiClient } from "../api/client.js";
import { readApiKey } from "../auth/keychain.js";
import { ConfigSchema } from "../config/sentinel.config.js";

const config = ConfigSchema.parse({
  apiUrl: "http://sentinel.test",
  repoName: "repo",
  provider: "local",
  model: "ollama"
});

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

test("api client starts device auth flow", async () => {
  let requestPath = "";
  globalThis.fetch = async (input: string | URL | Request, init?: RequestInit) => {
    requestPath = String(input);
    assert.equal(init?.method, "POST");
    return Response.json({
      device_code: "device-1",
      user_code: "ABCD-EFGH",
      verification_url: "/auth/device/verify",
      expires_in: 900
    });
  };

  const started = await new SentinelApiClient(config).startDeviceAuth();

  assert.equal(requestPath, "http://sentinel.test/auth/device");
  assert.equal(started.user_code, "ABCD-EFGH");
});

test("api client treats pending device token as non-error state", async () => {
  globalThis.fetch = async (input: string | URL | Request) => {
    assert.equal(String(input), "http://sentinel.test/auth/device/token?device_code=device-1");
    return new Response("authorization pending", { status: 202, statusText: "Accepted" });
  };

  const token = await new SentinelApiClient(config).deviceAuthToken("device-1");

  assert.deepEqual(token, { status: "pending" });
});

test("api client returns approved device auth token", async () => {
  globalThis.fetch = async (input: string | URL | Request) => {
    assert.equal(String(input), "http://sentinel.test/auth/device/token?device_code=device%2F1");
    return Response.json({
      access_token: "jwt",
      account_id: "account-1",
      user_id: "user-1"
    });
  };

  const token = await new SentinelApiClient(config).deviceAuthToken("device/1");

  assert.deepEqual(token, {
    status: "approved",
    access_token: "jwt",
    account_id: "account-1",
    user_id: "user-1"
  });
});
