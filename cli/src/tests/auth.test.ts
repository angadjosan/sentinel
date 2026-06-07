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

test("api client sends pentest finding id target", async () => {
  let body: Record<string, unknown> = {};
  globalThis.fetch = async (_input: string | URL | Request, init?: RequestInit) => {
    body = JSON.parse(String(init?.body));
    return Response.json({
      id: "finding-1",
      vuln_type: "sqli",
      severity: "high",
      title: "SQL injection",
      description: "desc",
      remediation: "fix",
      status: "open",
      confirmed: false,
      fingerprint: "fp"
    });
  };

  await new SentinelApiClient(config).pentest({ findingId: "123e4567-e89b-12d3-a456-426614174000" });

  assert.equal(body.finding_id, "123e4567-e89b-12d3-a456-426614174000");
  assert.equal(body.description, undefined);
});

test("api client sends pentest description and auto-select targets", async () => {
  const bodies: Array<Record<string, unknown>> = [];
  globalThis.fetch = async (_input: string | URL | Request, init?: RequestInit) => {
    bodies.push(JSON.parse(String(init?.body)));
    return Response.json({
      id: "finding-1",
      vuln_type: "cmdi",
      severity: "high",
      title: "Command injection",
      description: "desc",
      remediation: "fix",
      status: "open",
      confirmed: false,
      fingerprint: "fp"
    });
  };

  await new SentinelApiClient(config).pentest({ description: "command injection in image converter" });
  await new SentinelApiClient(config).pentest();

  assert.equal(bodies[0].description, "command injection in image converter");
  assert.equal(bodies[0].finding_id, undefined);
  assert.equal(bodies[1].description, undefined);
  assert.equal(bodies[1].finding_id, undefined);
});

test("api client cancels runs with DELETE", async () => {
  let requestPath = "";
  let method: string | undefined;
  globalThis.fetch = async (input: string | URL | Request, init?: RequestInit) => {
    requestPath = String(input);
    method = init?.method;
    return Response.json({
      id: "run-1",
      kind: "source",
      status: "cancelled",
      finding_count: 0,
      token_spend: 0,
      model_used: null,
      trace: "",
      created_at: "2026-06-06T00:00:00Z",
      completed_at: "2026-06-06T00:00:01Z"
    });
  };

  await new SentinelApiClient(config).cancelRun("run-1");

  assert.equal(requestPath, "http://sentinel.test/runs/run-1");
  assert.equal(method, "DELETE");
});
