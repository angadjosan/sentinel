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

    console.log(`Open ${verificationUrl}`);
    console.log(`Enter code: ${started.user_code}`);
    console.log(`Waiting for approval; code expires in ${Math.floor(started.expires_in / 60)} minute(s).`);

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
      writeConfig(ConfigSchema.parse({ apiUrl: options.apiUrl, repoName, provider: "local", model: "ollama" }), root);
      console.log(`wrote ${path}`);
    }
    const files: Record<string, string> = {};
    for (const file of lsFiles()) {
      if (file === "sentinel.config.json") continue;
      try {
        files[file] = readFileSync(join(root, file), "utf8");
      } catch {
        // Binary or unreadable tracked files are ignored by the bootstrap snapshot.
      }
    }
    const run = await new SentinelApiClient(loadConfig(root)).init(files);
    console.log(`initialized ${repoName}; run ${run.id}`);
  });

program
  .command("source")
  .description("Scan the current git diff")
  .argument("[paths...]", "Optional paths to scope the diff")
  .option("--staged", "Scan staged changes only")
  .option("--base <ref>", "Diff against this base ref")
  .option("--queue", "Queue scan for cloud worker instead of running synchronously")
  .action(async (paths: string[], options) => {
    validateConfigForScan(loadConfig());
    const diff = currentDiff({ staged: options.staged, base: options.base, paths });
    const runContext = process.env.CI ? "ci" : "local";
    const client = new SentinelApiClient();
    if (options.queue) {
      const queued = await client.enqueueSource(diff, runContext);
      console.log(`queued task ${queued.task_id}; run ${queued.run.id}`);
      return;
    }
    const result = await client.source(diff, runContext);
    for (const finding of result.findings) {
      console.log(`${chalk.red(finding.severity.toUpperCase())} ${finding.vuln_type} ${finding.id}`);
      console.log(`  ${finding.title}`);
      console.log(`  ${finding.description}`);
      console.log(`  fix: ${finding.remediation}`);
    }
    console.log(`run ${result.run.id} completed with ${result.findings.length} finding(s)`);
    process.exitCode = result.findings.length > 0 ? 1 : 0;
  });

program
  .command("scan")
  .description("Run source scan, then pentest each finding unless skipped")
  .option("--no-pentest", "Skip pentest")
  .action(async (options) => {
    validateConfigForScan(loadConfig());
    const client = new SentinelApiClient();
    const result = await client.source(currentDiff(), process.env.CI ? "ci" : "local");
    if (options.pentest) {
      for (const finding of result.findings) {
        await client.pentest(finding.id);
      }
    }
    console.log(`scan ${result.run.id}: ${result.findings.length} finding(s)`);
    process.exitCode = result.findings.length > 0 ? 1 : 0;
  });

program
  .command("list")
  .description("List findings")
  .action(async () => {
    const findings = await new SentinelApiClient().findings();
    for (const finding of findings) {
      console.log(`${finding.id}\t${finding.status}\t${finding.severity}\t${finding.vuln_type}\t${finding.title}`);
    }
  });

program
  .command("pull")
  .description("Fetch remediation context for a finding")
  .argument("<id>", "Finding ID")
  .action(async (id: string) => {
    const result = await new SentinelApiClient().pull(id);
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
    const result = await new SentinelApiClient().plan(content, Boolean(options.withRetry));
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
  .argument("<id>", "Finding ID")
  .option("--sanitizer-output <text>", "Sanitizer output")
  .option("--behavioral-proof <kind>", "Behavioral proof kind")
  .option("--proof-detail <text>", "Behavioral proof detail", "")
  .action(async (id: string, options) => {
    const finding = await new SentinelApiClient().pentest(id, options.sanitizerOutput ?? "", options.behavioralProof, options.proofDetail);
    console.log(`${finding.id}\t${finding.status}\tconfirmed=${finding.confirmed}`);
    if (finding.evidence) console.log(finding.evidence);
  });

const suppress = program.command("suppress").description("Suppress or remove suppressions");
suppress
  .argument("<id>", "Finding ID")
  .requiredOption("--reason <reason>", "Suppression reason")
  .action(async (id: string, options) => {
    const finding = await new SentinelApiClient().suppress(id, options.reason);
    console.log(`${finding.id}\t${finding.status}`);
  });
suppress
  .command("remove")
  .argument("<id>", "Finding ID")
  .requiredOption("--reason <reason>", "Unsuppression reason")
  .action(async (id: string, options) => {
    const finding = await new SentinelApiClient().unsuppress(id, options.reason);
    console.log(`${finding.id}\t${finding.status}`);
  });
suppress
  .command("approve")
  .argument("<id>", "Finding ID")
  .requiredOption("--reason <reason>", "Approval reason")
  .action(async (id: string, options) => {
    const finding = await new SentinelApiClient().approveSuppression(id, options.reason);
    console.log(`${finding.id}\t${finding.status}`);
  });
suppress
  .command("reject")
  .argument("<id>", "Finding ID")
  .requiredOption("--reason <reason>", "Rejection reason")
  .action(async (id: string, options) => {
    const finding = await new SentinelApiClient().rejectSuppression(id, options.reason);
    console.log(`${finding.id}\t${finding.status}`);
  });

const runs = program.command("runs").description("Manage run traces");
runs
  .command("list")
  .action(async () => {
    const rows = await new SentinelApiClient().runs();
    for (const run of rows) {
      console.log(`${run.id}\t${run.kind}\t${run.status}\t${run.token_spend}`);
    }
  });
runs
  .command("show")
  .argument("<id>", "Run ID")
  .action(async (id: string) => {
    const trace = await new SentinelApiClient().trace(id);
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
    const client = new SentinelApiClient();
    for await (const event of client.runEvents(id)) {
      console.log(event);
      try {
        const parsed = JSON.parse(event) as { kind?: string; status?: string };
        if (parsed.kind === "complete" || parsed.status === "failed" || parsed.status === "cancelled") break;
      } catch {
        // Non-JSON trace lines are still useful to display.
      }
    }
  });
runs
  .command("cancel")
  .argument("<id>", "Run ID")
  .action(async (id: string) => {
    const run = await new SentinelApiClient().cancelRun(id);
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
    if (key === "api-key") {
      await writeApiKey(ConfigSchema.parse(current), value);
      console.log("stored api-key in system keychain");
      return;
    }
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
    console.log(`set ${key}`);
  });

program.parseAsync().catch((error) => {
  console.error(chalk.red(`Error: ${error.message}`));
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
