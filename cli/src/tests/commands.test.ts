import assert from "node:assert/strict";
import { afterEach, test } from "node:test";

import { SentinelApiClient } from "../api/client.js";
import { ConfigSchema } from "../config/sentinel.config.js";

const config = ConfigSchema.parse({
  apiUrl: "http://sentinel.test",
  repoName: "test-repo",
  provider: "local",
  model: "ollama",
});

const FINDING = {
  id: "finding-1",
  vuln_type: "sqli",
  severity: "high",
  title: "SQL injection",
  description: "Unsanitized input reaches db.query",
  remediation: "Use parameterized queries",
  status: "open",
  confirmed: false,
  fingerprint: "fp-abc",
  file: "app.js",
  line_start: 12,
  line_end: 12,
  created_at: "2026-06-07T00:00:00Z",
  updated_at: "2026-06-07T00:00:00Z",
};

const RUN = {
  id: "run-1",
  kind: "source",
  status: "completed",
  finding_count: 1,
  token_spend: 800,
  model_used: "ollama",
  trace: "",
  created_at: "2026-06-07T00:00:00Z",
  completed_at: "2026-06-07T00:00:05Z",
};

const originalFetch = globalThis.fetch;

afterEach(() => {
  delete process.env.SENTINEL_API_TOKEN;
  globalThis.fetch = originalFetch;
});

// ---------------------------------------------------------------------------
// source
// ---------------------------------------------------------------------------

test("source sends diff and run_context to /source", async () => {
  process.env.SENTINEL_API_TOKEN = "tok";
  let body: Record<string, unknown> = {};
  globalThis.fetch = async (_input: string | URL | Request, init?: RequestInit) => {
    body = JSON.parse(String(init?.body));
    return Response.json({ run: RUN, findings: [FINDING] });
  };

  const result = await new SentinelApiClient(config).source("diff text", "local", {});

  assert.equal(body.diff, "diff text");
  assert.equal(body.run_context, "local");
  assert.equal(result.findings.length, 1);
  assert.equal(result.findings[0].vuln_type, "sqli");
});

test("source sends ci run_context when CI is set", async () => {
  process.env.SENTINEL_API_TOKEN = "tok";
  let capturedBody: Record<string, unknown> = {};
  globalThis.fetch = async (_input: string | URL | Request, init?: RequestInit) => {
    capturedBody = JSON.parse(String(init?.body));
    return Response.json({ run: RUN, findings: [] });
  };

  await new SentinelApiClient(config).source("diff", "ci", {});

  assert.equal(capturedBody.run_context, "ci");
});

test("source sends file path scope filter", async () => {
  process.env.SENTINEL_API_TOKEN = "tok";
  let capturedBody: Record<string, unknown> = {};
  globalThis.fetch = async (_input: string | URL | Request, init?: RequestInit) => {
    capturedBody = JSON.parse(String(init?.body));
    return Response.json({ run: RUN, findings: [] });
  };

  await new SentinelApiClient(config).source("diff", "local", { paths: ["src/auth.ts"] });

  assert.deepEqual(capturedBody.paths, ["src/auth.ts"]);
});

test("source throws on non-ok response", async () => {
  process.env.SENTINEL_API_TOKEN = "tok";
  globalThis.fetch = async () => new Response("internal error", { status: 500 });

  await assert.rejects(
    () => new SentinelApiClient(config).source("diff", "local"),
    /500/
  );
});

// ---------------------------------------------------------------------------
// enqueueSource
// ---------------------------------------------------------------------------

test("enqueueSource posts to /source/enqueue and returns task_id", async () => {
  process.env.SENTINEL_API_TOKEN = "tok";
  let path = "";
  globalThis.fetch = async (input: string | URL | Request, init?: RequestInit) => {
    path = String(input);
    assert.equal(init?.method, "POST");
    return Response.json({ task_id: "task-1", run: RUN });
  };

  const result = await new SentinelApiClient(config).enqueueSource("diff", "local");

  assert.equal(path, "http://sentinel.test/source/enqueue");
  assert.equal(result.task_id, "task-1");
});

// ---------------------------------------------------------------------------
// findings (list)
// ---------------------------------------------------------------------------

test("findings calls GET /findings with repo_name", async () => {
  process.env.SENTINEL_API_TOKEN = "tok";
  let requestPath = "";
  globalThis.fetch = async (input: string | URL | Request) => {
    requestPath = String(input);
    return Response.json([FINDING]);
  };

  const findings = await new SentinelApiClient(config).findings();

  assert.ok(requestPath.includes("/findings"), "should call /findings");
  assert.ok(requestPath.includes("repo_name=test-repo"));
  assert.equal(findings.length, 1);
});

test("findings passes status and severity filters", async () => {
  process.env.SENTINEL_API_TOKEN = "tok";
  let requestPath = "";
  globalThis.fetch = async (input: string | URL | Request) => {
    requestPath = String(input);
    return Response.json([FINDING]);
  };

  await new SentinelApiClient(config).findings({ status: "open", severity: "high" });

  assert.ok(requestPath.includes("status=open"));
  assert.ok(requestPath.includes("severity=high"));
});

// ---------------------------------------------------------------------------
// pull
// ---------------------------------------------------------------------------

test("pull calls GET /findings/{id}/pull", async () => {
  process.env.SENTINEL_API_TOKEN = "tok";
  let requestPath = "";
  globalThis.fetch = async (input: string | URL | Request) => {
    requestPath = String(input);
    return Response.json({
      finding: FINDING,
      node: { id: "fn:app.js:handler", kind: "FUNCTION" },
      remediation_plan: ["Use parameterized queries", "Sanitize input"],
    });
  };

  const result = await new SentinelApiClient(config).pull("finding-1");

  assert.equal(requestPath, "http://sentinel.test/findings/finding-1/pull");
  assert.equal(result.finding.id, "finding-1");
  assert.equal(result.remediation_plan.length, 2);
});

// ---------------------------------------------------------------------------
// plan
// ---------------------------------------------------------------------------

test("plan posts plan text to /plan", async () => {
  process.env.SENTINEL_API_TOKEN = "tok";
  let body: Record<string, unknown> = {};
  globalThis.fetch = async (_input: string | URL | Request, init?: RequestInit) => {
    body = JSON.parse(String(init?.body));
    return Response.json({ run: RUN, findings: [] });
  };

  await new SentinelApiClient(config).plan("Add a new user endpoint", false);

  assert.equal(body.content, "Add a new user endpoint");
  assert.equal(body.with_retry, false);
});

test("plan passes with_retry flag", async () => {
  process.env.SENTINEL_API_TOKEN = "tok";
  let body: Record<string, unknown> = {};
  globalThis.fetch = async (_input: string | URL | Request, init?: RequestInit) => {
    body = JSON.parse(String(init?.body));
    return Response.json({ run: RUN, findings: [] });
  };

  await new SentinelApiClient(config).plan("plan text", true);

  assert.equal(body.with_retry, true);
});

// ---------------------------------------------------------------------------
// suppress / unsuppress
// ---------------------------------------------------------------------------

test("suppress calls PATCH /findings/{id}/suppress with reason", async () => {
  process.env.SENTINEL_API_TOKEN = "tok";
  let requestPath = "";
  let body: Record<string, unknown> = {};
  globalThis.fetch = async (input: string | URL | Request, init?: RequestInit) => {
    requestPath = String(input);
    body = JSON.parse(String(init?.body));
    return Response.json({ ...FINDING, status: "suppressed", suppressed: true });
  };

  const result = await new SentinelApiClient(config).suppress("finding-1", "FP: test fixture");

  assert.equal(requestPath, "http://sentinel.test/findings/finding-1/suppress");
  assert.equal(body.reason, "FP: test fixture");
  assert.equal(result.status, "suppressed");
});

test("unsuppress calls POST /findings/{id}/unsuppress with reason", async () => {
  process.env.SENTINEL_API_TOKEN = "tok";
  let requestPath = "";
  let method: string | undefined;
  globalThis.fetch = async (input: string | URL | Request, init?: RequestInit) => {
    requestPath = String(input);
    method = init?.method;
    return Response.json({ ...FINDING, status: "open", suppressed: false });
  };

  await new SentinelApiClient(config).unsuppress("finding-1", "Reverting suppression");

  assert.equal(requestPath, "http://sentinel.test/findings/finding-1/unsuppress");
  assert.equal(method, "POST");
});

// ---------------------------------------------------------------------------
// runs list / show / cancel
// ---------------------------------------------------------------------------

test("runs list calls GET /runs", async () => {
  process.env.SENTINEL_API_TOKEN = "tok";
  let requestPath = "";
  globalThis.fetch = async (input: string | URL | Request) => {
    requestPath = String(input);
    return Response.json([RUN]);
  };

  const runs = await new SentinelApiClient(config).runs();

  assert.equal(requestPath, "http://sentinel.test/runs");
  assert.equal(runs.length, 1);
  assert.equal(runs[0].kind, "source");
});

test("run detail calls GET /runs/{id}", async () => {
  process.env.SENTINEL_API_TOKEN = "tok";
  let requestPath = "";
  globalThis.fetch = async (input: string | URL | Request) => {
    requestPath = String(input);
    return Response.json(RUN);
  };

  const run = await new SentinelApiClient(config).run("run-1");

  assert.equal(requestPath, "http://sentinel.test/runs/run-1");
  assert.equal(run.id, "run-1");
});

test("trace calls GET /runs/{id}/trace and returns text", async () => {
  process.env.SENTINEL_API_TOKEN = "tok";
  let requestPath = "";
  globalThis.fetch = async (input: string | URL | Request) => {
    requestPath = String(input);
    return new Response('{"kind":"scan_start"}\n{"kind":"finding"}', {
      status: 200,
      headers: { "Content-Type": "application/x-ndjson" },
    });
  };

  const trace = await new SentinelApiClient(config).trace("run-1");

  assert.equal(requestPath, "http://sentinel.test/runs/run-1/trace");
  assert.ok(trace.includes("scan_start"));
});

test("cancel run sends DELETE /runs/{id}", async () => {
  process.env.SENTINEL_API_TOKEN = "tok";
  let method: string | undefined;
  let requestPath = "";
  globalThis.fetch = async (input: string | URL | Request, init?: RequestInit) => {
    requestPath = String(input);
    method = init?.method;
    return Response.json({ ...RUN, status: "cancelled" });
  };

  const run = await new SentinelApiClient(config).cancelRun("run-1");

  assert.equal(requestPath, "http://sentinel.test/runs/run-1");
  assert.equal(method, "DELETE");
  assert.equal(run.status, "cancelled");
});

// ---------------------------------------------------------------------------
// scan (source + pentest per finding)
// ---------------------------------------------------------------------------

test("scan runs pentest for each finding in source result", async () => {
  process.env.SENTINEL_API_TOKEN = "tok";
  const calls: string[] = [];
  globalThis.fetch = async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    calls.push(url);
    if (url.endsWith("/source")) {
      return Response.json({ run: RUN, findings: [FINDING, { ...FINDING, id: "finding-2", fingerprint: "fp2" }] });
    }
    if (url.endsWith("/pentest")) {
      const body = JSON.parse(String(init?.body));
      return Response.json({ ...FINDING, id: body.finding_id, status: "confirmed", confirmed: true });
    }
    return new Response("not found", { status: 404 });
  };

  const client = new SentinelApiClient(config);
  const sourceResult = await client.source("diff", "local");
  const pentestResults = await Promise.all(
    sourceResult.findings.map((f) => client.pentest({ findingId: f.id }))
  );

  assert.equal(sourceResult.findings.length, 2);
  assert.equal(pentestResults.length, 2);
  assert.ok(calls.some((u) => u.endsWith("/source")));
  assert.ok(calls.some((u) => u.endsWith("/pentest")));
});

// ---------------------------------------------------------------------------
// error handling
// ---------------------------------------------------------------------------

test("api client throws on 401 unauthorized", async () => {
  delete process.env.SENTINEL_API_TOKEN;
  globalThis.fetch = async () => new Response("Unauthorized", { status: 401 });

  await assert.rejects(() => new SentinelApiClient(config).runs(), /401/);
});

test("api client throws on 422 validation error", async () => {
  process.env.SENTINEL_API_TOKEN = "tok";
  globalThis.fetch = async () =>
    new Response(JSON.stringify({ detail: "reason is required" }), {
      status: 422,
      headers: { "Content-Type": "application/json" },
    });

  await assert.rejects(() => new SentinelApiClient(config).suppress("finding-1", ""), /422/);
});
