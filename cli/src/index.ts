#!/usr/bin/env node
import { readFileSync, existsSync } from "node:fs";
import { basename, join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import chalk from "chalk";
import { Command } from "commander";

import { SentinelApiClient } from "./api/client.js";
import { writeApiKey } from "./auth/keychain.js";
import { ConfigSchema, configPath, findRepoRoot, loadConfig, validateConfigForScan, writeConfig } from "./config/sentinel.config.js";
import { currentDiff, lsFiles } from "./diff/git.js";

const program = new Command();

program.name("sentinel").description("Cloud-backed application security scanner").version("0.1.0");

const auth = program.command("auth").description("Manage Sentinel authentication");
auth
  .command("login")
  .description("Authorize this CLI with a browser-based device code")
  .option("--poll-interval <seconds>", "Polling interval while waiting for approval", "2")
  .action(async (options) => {
    const config = loadConfig();
    const client = new SentinelApiClient(config);
    const started = await client.startDeviceAuth();
    const verificationUrl = absoluteUrl(config.apiUrl, started.verification_url);
    const pollIntervalMs = Math.max(250, Math.floor(Number(options.pollInterval) * 1000));
    if (!Number.isFinite(pollIntervalMs)) {
      throw new Error("poll interval must be a number of seconds");
    }

    console.log(`Verification URL: ${verificationUrl}`);
    console.log(`User code:        ${started.user_code}`);
    console.log(`Polling for approval (dev mode auto-approves)...`);

    const deadline = Date.now() + started.expires_in * 1000;
    while (Date.now() < deadline) {
      const token = await client.deviceAuthToken(started.device_code);
      if (token.status === "approved") {
        await writeApiKey(config, token.access_token);
        console.log(`logged in as ${token.user_id} for account ${token.account_id}`);
        return;
      }
      await sleep(Math.min(pollIntervalMs, Math.max(0, deadline - Date.now())));
    }
    throw new Error("device code expired before approval");
  });

program
  .command("init")
  .description("Initialize Sentinel for this repository")
  .option("--api-url <url>", "Sentinel API URL", "http://localhost:8000")
  .option("--repo-name <name>", "Repository name")
  .action(async (options) => {
    const root = findRepoRoot();
    const path = configPath(root);
    const repoName = options.repoName ?? basename(root);
    if (!existsSync(path)) {
      writeConfig(ConfigSchema.parse({ apiUrl: options.apiUrl, repoName, provider: "local", model: "llama3.2" }), root);
      console.log(`wrote ${path}`);
    }
    const config = loadConfig(root);

    const files: Record<string, string> = {};
    for (const file of lsFiles()) {
      if (file === "sentinel.config.json") continue;
      try {
        files[file] = readFileSync(join(root, file), "utf8");
      } catch {
        // Binary or unreadable tracked files are ignored by the bootstrap snapshot.
      }
    }
    const run = await new SentinelApiClient(config).init(files);
    console.log(`initialized ${repoName}; run ${run.id}`);
  });

program
  .command("source")
  .description("Scan the current git diff")
  .argument("[paths...]", "Optional paths to scope the diff")
  .option("--staged", "Scan staged changes only")
  .option("--base <ref>", "Diff against this base ref")
  .option("--queue", "Queue scan for async worker (fire and forget)")
  .action(async (paths: string[], options) => {
    const config = loadConfig();
    validateConfigForScan(config);

    const diff = currentDiff({ staged: options.staged, base: options.base, paths });
    const client = new SentinelApiClient(config);
    const scope = { baseRef: options.base, paths };
    const runContext = process.env.CI ? "ci" : "local";

    if (options.queue) {
      const queued = await client.enqueueSource(diff, runContext, scope);
      console.log(`queued task ${queued.task_id}; run ${queued.run.id}`);
      return;
    }

    // Default: enqueue + stream findings live
    const queued = await client.enqueueSource(diff, runContext, scope);
    console.log(`run ${queued.run.id} started`);

    let findingCount = 0;
    const deadline = Date.now() + 120_000; // 2-min overall cap
    try {
      for await (const event of client.runEvents(queued.run.id, 120_000)) {
        try {
          const parsed = JSON.parse(event) as Record<string, unknown>;
          if (parsed.vuln_type) {
            findingCount++;
            console.log(`${chalk.red(((parsed.severity as string) || "unknown").toUpperCase())} ${parsed.vuln_type} ${parsed.id ?? ""}`);
            console.log(`  ${parsed.title ?? ""}`);
            if (parsed.remediation) console.log(`  fix: ${parsed.remediation}`);
          }
          const kind = parsed.kind as string | undefined;
          if (kind === "run.completed" || kind === "complete" || kind === "scan.completed" ||
              parsed.status === "failed" || parsed.status === "cancelled") {
            if (typeof parsed.finding_count === "number") findingCount = parsed.finding_count;
            break;
          }
        } catch { /* non-JSON trace lines */ }
        if (Date.now() > deadline) break;
      }
    } catch {
      // Stream interrupted — fall back to polling the run
      try {
        const run = await client.run(queued.run.id);
        findingCount = run.finding_count;
      } catch { /* ignore secondary error */ }
    }
    console.log(`run ${queued.run.id} completed with ${findingCount} finding(s)`);
    process.exitCode = findingCount > 0 ? 1 : 0;
  });

program
  .command("scan")
  .description("Run source scan, then pentest each finding unless skipped")
  .argument("[paths...]", "Optional paths to scope the diff")
  .option("--staged", "Scan staged changes only")
  .option("--base <ref>", "Diff against this base ref")
  .option("--no-pentest", "Skip pentest")
  .option("--pentest-concurrency <count>", "Maximum concurrent pentest jobs", "4")
  .action(async (paths: string[], options) => {
    validateConfigForScan(loadConfig());
    const config = loadConfig();

    const client = new SentinelApiClient(config);
    const diff = currentDiff({ staged: options.staged, base: options.base, paths });
    const scope = { baseRef: options.base, paths };
    const runContext = process.env.CI ? "ci" : "local";

    const queued = await client.enqueueSource(diff, runContext, scope);
    console.log(`run ${queued.run.id} started`);

    let findingCount = 0;
    const allFindings: Array<{ id: string }> = [];
    const deadline = Date.now() + 120_000;
    try {
      for await (const event of client.runEvents(queued.run.id, 120_000)) {
        try {
          const parsed = JSON.parse(event) as Record<string, unknown>;
          if (parsed.vuln_type && typeof parsed.id === "string") {
            findingCount++;
            allFindings.push({ id: parsed.id });
            console.log(`${chalk.red(((parsed.severity as string) || "unknown").toUpperCase())} ${parsed.vuln_type} ${parsed.id}`);
            console.log(`  ${parsed.title ?? ""}`);
          }
          const kind = parsed.kind as string | undefined;
          if (kind === "run.completed" || kind === "complete" || kind === "scan.completed" ||
              parsed.status === "failed" || parsed.status === "cancelled") {
            if (typeof parsed.finding_count === "number") findingCount = parsed.finding_count;
            break;
          }
        } catch { /* non-JSON */ }
        if (Date.now() > deadline) break;
      }
    } catch { /* stream interrupted */ }

    if (options.pentest && allFindings.length > 0) {
      const concurrency = parsePositiveInt(options.pentestConcurrency, "pentest concurrency");
      const pentestResults = await runLimited(allFindings, concurrency, async (finding) =>
        client.pentest({ findingId: finding.id })
      );
      for (const f of pentestResults) {
        console.log(`pentest ${f.id}: ${f.status} confirmed=${f.confirmed}`);
      }
    }
    console.log(`scan ${queued.run.id}: ${findingCount} finding(s)`);
    process.exitCode = findingCount > 0 ? 1 : 0;
  });

program
  .command("list")
  .description("List findings")
  .option("--status <status>", "Filter by finding status")
  .option("--severity <severity>", "Filter by severity")
  .action(async (options) => {
    const config = loadConfig();

    const findings = await new SentinelApiClient(config).findings({ status: options.status, severity: options.severity });
    console.log("ID\tSTATUS\tSEVERITY\tTYPE\tFILE\tUPDATED\tTITLE");
    for (const finding of findings) {
      const file = finding.file ? `${finding.file}${finding.line_start ? `:${finding.line_start}` : ""}` : "n/a";
      console.log(`${finding.id}\t${finding.status}\t${finding.severity}\t${finding.vuln_type}\t${file}\t${finding.updated_at}\t${finding.title}`);
    }
  });

program
  .command("pull")
  .description("Fetch remediation context for a finding")
  .argument("<id>", "Finding ID")
  .action(async (id: string) => {
    const config = loadConfig();

    const result = await new SentinelApiClient(config).pull(id);
    console.log(`${result.finding.severity.toUpperCase()} ${result.finding.vuln_type}: ${result.finding.title}`);
    console.log(result.finding.description);
    console.log("\nRemediation plan:");
    for (const item of result.remediation_plan) {
      console.log(`- ${item}`);
    }
    if (result.node) {
      console.log(`\nGraph node: ${JSON.stringify(result.node, null, 2)}`);
    }
  });

program
  .command("plan")
  .description("Review a plan file, stdin, or inline text for security issues")
  .argument("[input...]", "File path or inline text")
  .option("--with-retry", "Run retry review passes")
  .action(async (input: string[], options) => {
    const joined = input.join(" ");
    let content = joined;
    if (joined && existsSync(joined)) {
      content = readFileSync(joined, "utf8");
    } else if (!joined && !process.stdin.isTTY) {
      content = await new Promise<string>((resolve) => {
        let data = "";
        process.stdin.setEncoding("utf8");
        process.stdin.on("data", (chunk) => {
          data += chunk;
        });
        process.stdin.on("end", () => resolve(data));
      });
    }
    if (!content.trim()) {
      throw new Error("Provide a plan file, inline plan text, or stdin content.");
    }
    const config = loadConfig();

    const result = await new SentinelApiClient(config).plan(content, Boolean(options.withRetry));
    for (const finding of result.findings) {
      console.log(`${chalk.red(finding.severity.toUpperCase())} ${finding.vuln_type}: ${finding.title}`);
      console.log(`  ${finding.description}`);
      console.log(`  fix: ${finding.remediation}`);
    }
    console.log(`plan run ${result.run.id} completed with ${result.findings.length} issue(s)`);
    process.exitCode = result.findings.length > 0 ? 1 : 0;
  });

program
  .command("pentest")
  .description("Attempt to confirm a finding with oracle evidence")
  .argument("[target...]", "Finding ID, natural-language target, or empty to auto-select")
  .option("--sanitizer-output <text>", "Sanitizer output")
  .option("--behavioral-proof <kind>", "Behavioral proof kind")
  .option("--proof-detail <text>", "Behavioral proof detail", "")
  .action(async (targetParts: string[], options) => {
    const config = loadConfig();

    const target = parsePentestTarget(targetParts);
    const finding = await new SentinelApiClient(config).pentest(target, options.sanitizerOutput ?? "", options.behavioralProof, options.proofDetail);
    console.log(`${finding.id}\t${finding.status}\tconfirmed=${finding.confirmed}`);
    if (finding.evidence) console.log(finding.evidence);
  });

const suppress = program.command("suppress").description("Suppress or remove suppressions");
suppress
  .argument("<id>", "Finding ID")
  .requiredOption("--reason <reason>", "Suppression reason")
  .action(async (id: string, options) => {
    const config = loadConfig();

    const finding = await new SentinelApiClient(config).suppress(id, options.reason);
    console.log(`${finding.id}\t${finding.status}`);
  });
suppress
  .command("remove")
  .argument("<id>", "Finding ID")
  .requiredOption("--reason <reason>", "Unsuppression reason")
  .action(async (id: string, options) => {
    const config = loadConfig();

    const finding = await new SentinelApiClient(config).unsuppress(id, options.reason);
    console.log(`${finding.id}\t${finding.status}`);
  });
suppress
  .command("approve")
  .argument("<id>", "Finding ID")
  .requiredOption("--reason <reason>", "Approval reason")
  .action(async (id: string, options) => {
    const config = loadConfig();

    const finding = await new SentinelApiClient(config).approveSuppression(id, options.reason);
    console.log(`${finding.id}\t${finding.status}`);
  });
suppress
  .command("reject")
  .argument("<id>", "Finding ID")
  .requiredOption("--reason <reason>", "Rejection reason")
  .action(async (id: string, options) => {
    const config = loadConfig();

    const finding = await new SentinelApiClient(config).rejectSuppression(id, options.reason);
    console.log(`${finding.id}\t${finding.status}`);
  });

const runs = program.command("runs").description("Manage run traces");
runs
  .command("list")
  .action(async () => {
    const config = loadConfig();

    const rows = await new SentinelApiClient(config).runs();
    console.log("ID\tKIND\tSTATUS\tFINDINGS\tTOKENS\tMODEL\tCREATED");
    for (const run of rows) {
      console.log(`${run.id}\t${run.kind}\t${run.status}\t${run.finding_count}\t${run.token_spend}\t${run.model_used ?? "n/a"}\t${run.created_at}`);
    }
  });
runs
  .command("show")
  .argument("<id>", "Run ID")
  .action(async (id: string) => {
    const config = loadConfig();

    const trace = await new SentinelApiClient(config).trace(id);
    console.log(trace);
    const summary = summarizeTokens(trace);
    if (summary.totalInput + summary.totalOutput > 0) {
      console.log("\n--- Token Summary ---");
      for (const row of summary.rows) {
        console.log(`  ${row.component}: ${row.input.toLocaleString()} in + ${row.output.toLocaleString()} out = ${(row.input + row.output).toLocaleString()}`);
      }
      console.log(`  Total: ${summary.totalInput.toLocaleString()} in + ${summary.totalOutput.toLocaleString()} out = ${(summary.totalInput + summary.totalOutput).toLocaleString()}`);
    }
  });
runs
  .command("watch")
  .argument("<id>", "Run ID")
  .action(async (id: string) => {
    const config = loadConfig();

    const client = new SentinelApiClient(config);
    for await (const event of client.runEvents(id)) {
      console.log(event);
      try {
        const parsed = JSON.parse(event) as { kind?: string; status?: string };
        if (parsed.kind === "run.completed" || parsed.kind === "complete" || parsed.status === "failed" || parsed.status === "cancelled") break;
      } catch {
        // Non-JSON trace lines are still useful to display.
      }
    }
  });
runs
  .command("cancel")
  .argument("<id>", "Run ID")
  .action(async (id: string) => {
    const config = loadConfig();

    const run = await new SentinelApiClient(config).cancelRun(id);
    console.log(`${run.id}\t${run.status}`);
  });

const config = program.command("config").description("Manage local Sentinel config");
config.command("show").action(() => {
  console.log(JSON.stringify(loadConfig(), null, 2));
});
config
  .command("set")
  .argument("<key>", "Config key")
  .argument("<value>", "Config value")
  .action(async (key: string, value: string) => {
    const root = findRepoRoot();
    const current = loadConfig(root) as Record<string, unknown>;
    const client = new SentinelApiClient();

    if (key === "api-key") {
      await client.patchConfig({ api_key: value });
      console.log("api-key stored on server");
      return;
    }

    const serverSyncKeys = new Set(["provider", "model", "api_endpoint"]);
    const allowed = new Set(["apiUrl", "repoName", "provider", "model", "boot", "healthcheck", "api_endpoint", "repo_id"]);

    if (key.startsWith("firecracker.")) {
      setFirecrackerConfigValue(current, key.slice("firecracker.".length), value);
      writeConfig(ConfigSchema.parse(current), root);
      console.log(`set ${key}`);
      return;
    }
    if (!allowed.has(key)) {
      throw new Error(`Unsupported config key ${key}`);
    }
    current[key] = value;
    writeConfig(ConfigSchema.parse(current), root);

    if (serverSyncKeys.has(key)) {
      const patch: Record<string, string | null> = {};
      patch[key] = value;
      await client.patchConfig(patch as { provider?: string; model?: string; api_endpoint?: string | null });
      console.log(`set ${key} (local + server)`);
    } else {
      console.log(`set ${key}`);
    }
  });

program.parseAsync().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(chalk.red(`Error: ${message}`));
  if (process.env.DEBUG && error instanceof Error && error.stack) {
    console.error(error.stack);
  }
  if (error instanceof Error && (error as NodeJS.ErrnoException).cause) {
    const cause = (error as NodeJS.ErrnoException).cause as any;
    const causeStr = cause?.code ?? String(cause);
    if (causeStr !== message) {
      console.error(chalk.dim(`Cause: ${causeStr}`));
    }
  }
  process.exitCode = 2;
});

function summarizeTokens(trace: string): { rows: Array<{ component: string; input: number; output: number }>; totalInput: number; totalOutput: number } {
  const totals = new Map<string, { input: number; output: number }>();
  for (const line of trace.split("\n")) {
    if (!line.trim()) continue;
    try {
      const event = JSON.parse(line) as { kind?: string; component?: string; input_tokens?: number; output_tokens?: number };
      if (event.kind !== "token_event" || !event.component) continue;
      const current = totals.get(event.component) ?? { input: 0, output: 0 };
      current.input += event.input_tokens ?? 0;
      current.output += event.output_tokens ?? 0;
      totals.set(event.component, current);
    } catch {
      continue;
    }
  }
  const rows = Array.from(totals.entries()).map(([component, counts]) => ({ component, input: counts.input, output: counts.output }));
  return {
    rows,
    totalInput: rows.reduce((sum, row) => sum + row.input, 0),
    totalOutput: rows.reduce((sum, row) => sum + row.output, 0)
  };
}

function absoluteUrl(apiUrl: string, pathOrUrl: string): string {
  return new URL(pathOrUrl, apiUrl).toString();
}

async function runLimited<T, R>(items: T[], concurrency: number, task: (item: T) => Promise<R>): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let nextIndex = 0;
  const workers = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (nextIndex < items.length) {
      const index = nextIndex;
      nextIndex += 1;
      results[index] = await task(items[index]);
    }
  });
  await Promise.all(workers);
  return results;
}

function parsePositiveInt(value: string, label: string): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error(`${label} must be a positive integer`);
  }
  return parsed;
}

function parsePentestTarget(parts: string[]): { findingId?: string; description?: string } {
  const target = parts.join(" ").trim();
  if (!target) return {};
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(target)) {
    return { findingId: target };
  }
  return { description: target };
}

function setFirecrackerConfigValue(config: Record<string, unknown>, key: string, value: string): void {
  const current = (config.firecracker && typeof config.firecracker === "object" ? config.firecracker : {}) as Record<string, unknown>;
  if (key === "enabled" || key === "smt") {
    current[key] = value === "true";
  } else if (key === "vcpu_count" || key === "mem_size_mib") {
    current[key] = Number(value);
  } else if (key === "guest_runner_argv") {
    current[key] = value.split(/\s+/).filter(Boolean);
  } else if (
    [
      "kernel_image",
      "rootfs_image",
      "api_socket",
      "firecracker_bin",
      "boot_args",
      "network_interface_id",
      "host_dev_name",
      "guest_mac"
    ].includes(key)
  ) {
    current[key] = value;
  } else {
    throw new Error(`Unsupported firecracker config key ${key}`);
  }
  config.firecracker = current;
}
