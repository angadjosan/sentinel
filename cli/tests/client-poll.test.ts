import { test } from "node:test";
import assert from "node:assert/strict";
import { SentinelApiClient } from "../src/api/client.js";
import type { SentinelConfig } from "../src/config/sentinel.config.js";

test("runEvents polls run trace until terminal", async () => {
  const snapshots = [
    { id: "r1", kind: "source", status: "running", trace: "task.queued\ntask.claimed", finding_count: 0, token_spend: 0, created_at: "" },
    { id: "r1", kind: "source", status: "completed", trace: "task.queued\ntask.claimed\ntask.completed", finding_count: 0, token_spend: 0, created_at: "" },
  ];
  let call = 0;
  const origFetch = globalThis.fetch;
  globalThis.fetch = (async (_url: string | URL | Request) => ({
    ok: true,
    status: 200,
    json: async () => snapshots[Math.min(call++, snapshots.length - 1)],
    text: async () => "",
  })) as unknown as typeof fetch;

  try {
    const fakeConfig = { apiUrl: "https://x", repoName: "d" } as unknown as SentinelConfig;
    const client = new SentinelApiClient(fakeConfig);
    const seen: string[] = [];
    for await (const line of client.runEvents("r1", 5000)) seen.push(line);
    assert.deepEqual(seen, ["task.queued", "task.claimed", "task.completed"]);
  } finally {
    globalThis.fetch = origFetch;
  }
});
