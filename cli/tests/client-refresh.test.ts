import { test } from "node:test";
import assert from "node:assert/strict";
import { SentinelApiClient } from "../src/api/client.js";
import { clearApiKey, readCredential, writeCredential } from "../src/auth/keychain.js";
import type { SentinelConfig } from "../src/config/sentinel.config.js";

// Distinctive apiUrl so any keychain file-fallback writes are isolated from real credentials.
const fakeConfig = { apiUrl: "https://test-refresh.invalid", repoName: "client-refresh-test" } as unknown as SentinelConfig;

test("request() transparently refreshes an expired access token and retries once", async () => {
  await writeCredential(fakeConfig, { accessToken: "expired-access", refreshToken: "valid-refresh" });

  const calls: string[] = [];
  const origFetch = globalThis.fetch;
  globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
    const path = String(url).replace(fakeConfig.apiUrl, "");
    calls.push(path);
    if (path === "/auth/refresh") {
      assert.equal(JSON.parse(String(init?.body)).refresh_token, "valid-refresh");
      return {
        ok: true,
        status: 200,
        json: async () => ({ access_token: "fresh-access", refresh_token: "rotated-refresh" }),
        text: async () => "",
      };
    }
    const isFirstAttempt = calls.filter((c) => c === "/findings").length === 1;
    if (isFirstAttempt) {
      return { ok: false, status: 401, json: async () => ({}), text: async () => "expired" };
    }
    assert.equal((init?.headers as Record<string, string>)?.Authorization, "Bearer fresh-access");
    return { ok: true, status: 200, json: async () => [{ id: "f1" }], text: async () => "" };
  }) as unknown as typeof fetch;

  try {
    const client = new SentinelApiClient(fakeConfig);
    const result = await client.request<Array<{ id: string }>>("/findings");
    assert.deepEqual(result, [{ id: "f1" }]);
    assert.deepEqual(calls, ["/findings", "/auth/refresh", "/findings"]);

    const stored = await readCredential(fakeConfig);
    assert.equal(stored?.accessToken, "fresh-access");
    assert.equal(stored?.refreshToken, "rotated-refresh");
  } finally {
    globalThis.fetch = origFetch;
    await clearApiKey(fakeConfig);
  }
});

test("request() surfaces the original 401 when there is no refresh token to fall back on", async () => {
  await writeCredential(fakeConfig, { accessToken: "expired-access" });

  const origFetch = globalThis.fetch;
  globalThis.fetch = (async () => ({
    ok: false,
    status: 401,
    json: async () => ({}),
    text: async () => "expired",
  })) as unknown as typeof fetch;

  try {
    const client = new SentinelApiClient(fakeConfig);
    await assert.rejects(() => client.request("/findings"), /401/);
  } finally {
    globalThis.fetch = origFetch;
    await clearApiKey(fakeConfig);
  }
});
