#!/usr/bin/env node
import { readFileSync, existsSync } from "node:fs";
import { basename, join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import chalk from "chalk";
import { Command } from "commander";

import { type Finding, type Run, SentinelApiClient } from "./api/client.js";
import { writeApiKey } from "./auth/keychain.js";
import { ConfigSchema, configPath, findRepoRoot, loadConfig, validateConfigForScan, writeConfig } from "./config/sentinel.config.js";
import { currentDiff, lsFiles } from "./diff/git.js";

const program = new Command();

program.name("sentinel").description("Cloud-backed application security scanner").version("0.1.0");

program.action(async () => {
  await showGreeting();
});

// ── Spinner ──────────────────────────────────────────────────────────────────

const activeSpinners = new Set<Spinner>();

class Spinner {
  private timer: ReturnType<typeof setInterval> | null = null;
  private frame = 0;
  private readonly frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
  private _text: string;
  private readonly isTTY: boolean;

  constructor(text: string) {
    this._text = text;
    this.isTTY = Boolean(process.stdout.isTTY);
    activeSpinners.add(this);
    if (this.isTTY) {
      this.timer = setInterval(() => {
        process.stdout.write(`\r  ${chalk.cyan(this.frames[this.frame++ % this.frames.length])}  ${this._text}  `);
      }, 80);
    } else {
      process.stderr.write(`  ${text}\n`);
    }
  }

  update(text: string) {
    this._text = text;
    if (!this.isTTY) process.stderr.write(`  ${text}\n`);
  }

  succeed(text: string) {
    this.stop();
    console.log(`  ${chalk.green("✓")}  ${text}`);
  }

  fail(text: string) {
    this.stop();
    console.log(`  ${chalk.red("✗")}  ${chalk.bold(text)}`);
  }

  stop() {
    if (this.timer) { clearInterval(this.timer); this.timer = null; }
    if (this.isTTY) process.stdout.write("\r\x1b[K");
    activeSpinners.delete(this);
  }
}

// ── Display helpers ───────────────────────────────────────────────────────────

const SEVERITY_COLORS: Record<string, (s: string) => string> = {
  critical: (s) => chalk.bgRed.white.bold(s),
  high:     (s) => chalk.bgRedBright.black.bold(s),
  medium:   (s) => chalk.bgYellow.black.bold(s),
  low:      (s) => chalk.bgBlue.white(s),
  info:     (s) => chalk.bgGray.white(s),
};

function severityBadge(severity: string): string {
  const fn = SEVERITY_COLORS[severity.toLowerCase()] ?? ((s: string) => chalk.bgGray.white(s));
  return fn(` ${severity.toUpperCase()} `);
}

function severityColor(severity: string): (s: string) => string {
  if (severity === "critical" || severity === "high") return chalk.red;
  if (severity === "medium") return chalk.yellow;
  return chalk.blue;
}

function printFinding(finding: Finding, index?: number): void {
  const num = index !== undefined ? chalk.dim(`${index + 1}. `) : "   ";
  const loc = finding.file
    ? chalk.dim(`  ${finding.file}${finding.line_start ? `:${finding.line_start}` : ""}`)
    : "";
  const confirmed = finding.confirmed ? chalk.green(" [CONFIRMED]") : "";
  console.log(`\n  ${num}${severityBadge(finding.severity)}${confirmed}  ${chalk.bold(finding.title)}${loc}`);
  console.log(`       ${chalk.dim(finding.vuln_type)}  ·  ${chalk.dim(finding.id.slice(0, 8))}`);
  console.log(`       ${severityColor(finding.severity)(finding.description)}`);
  if (finding.remediation) {
    console.log(`       ${chalk.cyan("→")} ${finding.remediation}`);
  }
}

function printFindings(findings: Finding[]): void {
  if (findings.length === 0) return;
  for (let i = 0; i < findings.length; i++) printFinding(findings[i], i);
}

function findingSummary(findings: Finding[]): string {
  if (findings.length === 0) return chalk.green("No issues found");
  const counts: Record<string, number> = {};
  for (const f of findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  const parts: string[] = [];
  for (const sev of ["critical", "high", "medium", "low", "info"]) {
    if (counts[sev]) parts.push(severityColor(sev)(`${counts[sev]} ${sev}`));
  }
  return `${chalk.bold(findings.length)} issue${findings.length !== 1 ? "s" : ""}  ·  ${parts.join("  ·  ")}`;
}

function formatTable(headers: string[], rows: string[][]): void {
  if (rows.length === 0) return;
  const allRows = [headers, ...rows];
  const widths = headers.map((_, i) => Math.max(...allRows.map((r) => (r[i] ?? "").length)));
  const rule = chalk.dim(widths.map((w) => "─".repeat(w)).join("  "));
  console.log(`\n  ${headers.map((h, i) => chalk.dim(h.padEnd(widths[i]))).join("  ")}`);
  console.log(`  ${rule}`);
  for (const row of rows) {
    console.log(`  ${row.map((cell, i) => (cell ?? "").padEnd(widths[i])).join("  ")}`);
  }
}

function formatElapsed(startMs: number): string {
  return `${((Date.now() - startMs) / 1000).toFixed(1)}s`;
}

function fmtDate(iso: string): string {
  return iso.replace("T", " ").slice(0, 19);
}

function diffFileCount(diff: string): number {
  return (diff.match(/^diff --git /gm) ?? []).length;
}

// ── Error handler ─────────────────────────────────────────────────────────────

function die(error: unknown): never {
  for (const s of activeSpinners) s.stop();
  activeSpinners.clear();

  const msg = error instanceof Error ? error.message : String(error);
  let apiUrl = "http://localhost:8000";
  try { apiUrl = loadConfig().apiUrl; } catch { /* ignore */ }

  console.error("");

  if (msg.includes("ECONNREFUSED") || msg.includes("fetch failed") || msg.includes("Failed to fetch")) {
    console.error(`  ${chalk.red("✗")}  ${chalk.bold("Cannot connect to the Sentinel API")}`);
    console.error(`     URL:   ${chalk.dim(apiUrl)}`);
    console.error(`     Fix:   ${chalk.white("docker compose up")}`);
  } else if (msg.includes("401") || msg.toLowerCase().includes("unauthorized")) {
    console.error(`  ${chalk.red("✗")}  ${chalk.bold("Not authenticated")}`);
    console.error(`     Fix:   ${chalk.white("sentinel auth login")}`);
  } else if (msg.includes("LLM authentication failed")) {
    console.error(`  ${chalk.red("✗")}  ${chalk.bold("LLM API key is invalid or missing")}`);
    console.error(`     Fix:   ${chalk.white("sentinel config set api-key <your-key>")}`);
  } else if (msg.includes("LLM not configured")) {
    console.error(`  ${chalk.red("✗")}  ${chalk.bold("LLM provider not configured")}`);
    console.error(`     Ollama:    ${chalk.white("sentinel config set provider local")}`);
    console.error(`     Anthropic: ${chalk.white("sentinel config set provider anthropic && sentinel config set api-key <key>")}`);
  } else if (msg.includes("sentinel.config.json not found")) {
    console.error(`  ${chalk.red("✗")}  ${chalk.bold("Repository not initialized")}`);
    console.error(`     Fix:   ${chalk.white("sentinel init")}`);
  } else if (msg.includes("device code expired")) {
    console.error(`  ${chalk.red("✗")}  ${chalk.bold("Authorization timed out")}`);
    console.error(`     Fix:   ${chalk.white("sentinel auth login")}`);
  } else if (msg.includes("Unsupported config key")) {
    console.error(`  ${chalk.red("✗")}  ${chalk.bold(msg)}`);
    console.error(`     Valid keys: apiUrl, repoName, provider, model, boot, healthcheck, api_endpoint`);
  } else {
    console.error(`  ${chalk.red("✗")}  ${chalk.bold(msg)}`);
  }

  console.error("");
  process.exit(2);
}

// ── Greeting ─────────────────────────────────────────────────────────────────

async function showGreeting(): Promise<void> {
  const eyeFrames = [
    ["        ██████████        ","      ██          ██      ","    ██              ██    ","   ██  ████          ██   ","  ██  ██████          ██  ","  ██  ████            ██  ","   ██                ██   ","    ██              ██    ","      ██          ██      ","        ██████████        "],
    ["        ██████████        ","      ██          ██      ","    ██              ██    ","   ██                ██   ","  ██                  ██  ","  ██  ████            ██  ","   ██ ██████         ██   ","    ██████          ██    ","      ██          ██      ","        ██████████        "],
    ["        ██████████        ","      ██          ██      ","    ██              ██    ","   ██      ████    ██   ","  ██      ██████    ██  ","  ██      ████      ██  ","   ██                ██   ","    ██              ██    ","      ██          ██      ","        ██████████        "],
    ["        ██████████        ","      ██          ██      ","    ██              ██    ","   ██          ████  ██   ","  ██          ██████  ██  ","  ██            ████  ██  ","   ██                ██   ","    ██              ██    ","      ██          ██      ","        ██████████        "],
    ["        ██████████        ","      ██          ██      ","    ██        ████  ██    ","   ██        ██████  ██   ","  ██          ████    ██  ","  ██                  ██  ","   ██                ██   ","    ██              ██    ","      ██          ██      ","        ██████████        "],
    ["        ██████████        ","      ██          ██      ","    ██    ████      ██    ","   ██    ██████      ██   ","  ██      ████      ██  ","  ██                  ██  ","   ██                ██   ","    ██              ██    ","      ██          ██      ","        ██████████        "],
    ["        ██████████        ","      ██          ██      ","    ██              ██    ","   ██      ████    ██   ","  ██      ██████    ██  ","  ██      ████      ██  ","   ██                ██   ","    ██              ██    ","      ██          ██      ","        ██████████        "],
  ];

  const sequence = [0, 1, 2, 3, 4, 5, 2, 0, 3, 5, 4, 2, 6];
  const frameHeight = eyeFrames[0].length;
  process.stdout.write("\n");

  for (let i = 0; i < sequence.length; i++) {
    const frame = eyeFrames[sequence[i]];
    const isLast = i === sequence.length - 1;
    const delay = isLast ? 0 : (i >= sequence.length - 3 ? 180 : 120);
    if (i > 0) process.stdout.write(`\x1b[${frameHeight}A`);
    for (const line of frame) process.stdout.write(`    ${chalk.cyan(line)}\n`);
    if (!isLast) await sleep(delay);
  }

  process.stdout.write("\n");
  console.log(chalk.bold.white("  ╔══════════════════════════════════════════════════════╗"));
  console.log(chalk.bold.white("  ║") + chalk.bold.cyan("          S E N T I N E L   v0.1.0                   ") + chalk.bold.white("║"));
  console.log(chalk.bold.white("  ║") + chalk.dim("      Application Security Agent for your code        ") + chalk.bold.white("║"));
  console.log(chalk.bold.white("  ╚══════════════════════════════════════════════════════╝"));
  console.log();
  console.log(chalk.bold.underline("  USAGE"));
  console.log();
  console.log(`    ${chalk.white("$")} ${chalk.green("sentinel")} ${chalk.yellow("<command>")} ${chalk.dim("[options]")}`);
  console.log();
  console.log(chalk.bold.underline("  COMMANDS"));
  console.log();

  const commands: Array<[string, string, string]> = [
    ["Setup", "", ""],
    ["", "init", "Initialize Sentinel for the current repository"],
    ["", "auth login", "Authenticate with browser-based device code"],
    ["", "config show", "Display current configuration"],
    ["", "config set <key> <val>", "Update a config value"],
    ["Scanning", "", ""],
    ["", "source [paths...]", "Scan the current git diff for vulnerabilities"],
    ["", "scan [paths...]", "Full scan: SAST analysis + automated pentesting"],
    ["", "plan <file|text>", "Review a plan or design doc for security issues"],
    ["", "pentest [target]", "Manually pentest a specific finding"],
    ["Findings", "", ""],
    ["", "list", "List all findings with optional filters"],
    ["", "pull <id>", "Fetch remediation context for a finding"],
    ["", "suppress <id>", "Suppress a finding (with approval workflow)"],
    ["Runs", "", ""],
    ["", "runs list", "List all scan run traces"],
    ["", "runs show <id>", "Show run details with token summary"],
    ["", "runs watch <id>", "Stream live run events"],
    ["", "runs cancel <id>", "Cancel an in-progress run"],
  ];

  for (const [section, cmd, desc] of commands) {
    if (section && !cmd) {
      console.log(`  ${chalk.bold.cyan(section)}`);
    } else {
      console.log(`    ${chalk.green(cmd.padEnd(26))} ${chalk.dim(desc)}`);
    }
  }

  console.log();
  console.log(chalk.bold.underline("  QUICK START"));
  console.log();
  console.log(`    ${chalk.dim("1.")} ${chalk.white("sentinel init")}${chalk.dim("                    # set up repo + build code graph")}`);
  console.log(`    ${chalk.dim("2.")} ${chalk.white("sentinel config set provider local")}${chalk.dim("  # use Ollama (already default)")}`);
  console.log(`    ${chalk.dim("3.")} ${chalk.white("sentinel source")}${chalk.dim("                  # scan your latest changes")}`);
  console.log(`    ${chalk.dim("4.")} ${chalk.white("sentinel list")}${chalk.dim("                    # review findings")}`);
  console.log(`    ${chalk.dim("5.")} ${chalk.white("sentinel pull <id>")}${chalk.dim("               # get fix guidance")}`);
  console.log();
  console.log(`  ${chalk.dim("Run")} ${chalk.white("sentinel <command> --help")} ${chalk.dim("for detailed usage of any command.")}`);
  console.log();
}

// ── Commands ──────────────────────────────────────────────────────────────────

const auth = program.command("auth").description("Manage Sentinel authentication");
auth
  .command("login")
  .description("Authorize this CLI with a browser-based device code")
  .option("--poll-interval <seconds>", "Polling interval while waiting for approval", "2")
  .action(async (options) => {
    const config = loadConfig();
    const client = new SentinelApiClient(config);

    const spin = new Spinner("Starting device authorization...");
    const started = await client.startDeviceAuth();
    spin.succeed("Device authorization started");

    const verificationUrl = absoluteUrl(config.apiUrl, started.verification_url);
    console.log(`\n     Verify at:  ${chalk.cyan(verificationUrl)}`);
    console.log(`     Code:       ${chalk.bold.white(started.user_code)}\n`);

    const pollIntervalMs = Math.max(250, Math.floor(Number(options.pollInterval) * 1000));
    if (!Number.isFinite(pollIntervalMs)) throw new Error("poll interval must be a number of seconds");

    const spin2 = new Spinner("Waiting for approval...  (dev mode auto-approves)");
    const deadline = Date.now() + started.expires_in * 1000;
    while (Date.now() < deadline) {
      const token = await client.deviceAuthToken(started.device_code);
      if (token.status === "approved") {
        await writeApiKey(config, token.access_token);
        spin2.succeed(`Logged in  ${chalk.dim(`·  account: ${token.account_id}`)}`);
        return;
      }
      await sleep(Math.min(pollIntervalMs, Math.max(0, deadline - Date.now())));
    }
    spin2.fail("Authorization timed out");
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
      console.log(`  ${chalk.dim("→")}  Config written to ${chalk.dim(path)}`);
    }

    const files: Record<string, string> = {};
    const allFiles = lsFiles().filter((f) => f !== "sentinel.config.json");
    for (const file of allFiles) {
      try { files[file] = readFileSync(join(root, file), "utf8"); } catch { /* skip binary */ }
    }

    const spin = new Spinner(`Uploading ${Object.keys(files).length} files and building code graph...`);
    const t = Date.now();
    const run = await new SentinelApiClient(loadConfig(root)).init(files);
    spin.succeed(`Repository initialized  ${chalk.dim(`·  ${formatElapsed(t)}`)}`);
    console.log(`\n     Repo:  ${chalk.bold(repoName)}`);
    console.log(`     Run:   ${chalk.dim(run.id)}\n`);
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
    const { diff, label } = currentDiff({ staged: options.staged, base: options.base, paths });
    const fileCount = diffFileCount(diff);
    const runContext = process.env.CI ? "ci" : "local";
    const client = new SentinelApiClient();
    const scope = { baseRef: options.base, paths };

    if (options.queue) {
      const spin = new Spinner("Queuing scan...");
      const queued = await client.enqueueSource(diff, runContext, scope);
      spin.succeed(`Scan queued`);
      console.log(`\n     Task:  ${chalk.dim(queued.task_id)}`);
      console.log(`     Run:   ${chalk.dim(queued.run.id)}\n`);
      return;
    }

    console.log(`\n  Scanning ${chalk.bold(label)}${fileCount ? chalk.dim(`  ·  ${fileCount} file${fileCount !== 1 ? "s" : ""}`) : ""}\n`);
    const spin = new Spinner("Analyzing...");
    const t = Date.now();
    const result = await client.source(diff, runContext, scope);
    spin.succeed(`Scan complete  ${chalk.dim(`·  ${formatElapsed(t)}`)}  ·  ${findingSummary(result.findings)}`);

    printFindings(result.findings);

    if (result.findings.length === 0) {
      console.log(`\n  ${chalk.green("✓")}  ${chalk.bold("No issues found")}\n`);
    } else {
      console.log(`\n  ${findingSummary(result.findings)}\n`);
    }

    process.exitCode = result.findings.length > 0 ? 1 : 0;
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
    const client = new SentinelApiClient();
    const { diff, label } = currentDiff({ staged: options.staged, base: options.base, paths });
    const fileCount = diffFileCount(diff);

    console.log(`\n  Scanning ${chalk.bold(label)}${fileCount ? chalk.dim(`  ·  ${fileCount} file${fileCount !== 1 ? "s" : ""}`) : ""}\n`);

    const spin = new Spinner("Analyzing...");
    const t = Date.now();
    const result = await client.source(diff, process.env.CI ? "ci" : "local", { baseRef: options.base, paths });
    spin.succeed(`Analysis complete  ${chalk.dim(`·  ${formatElapsed(t)}`)}  ·  ${result.findings.length} finding${result.findings.length !== 1 ? "s" : ""}`);

    let findings = result.findings;

    if (options.pentest && findings.length > 0) {
      const concurrency = parsePositiveInt(options.pentestConcurrency, "pentest concurrency");
      const spin2 = new Spinner(`Pentesting ${findings.length} finding${findings.length !== 1 ? "s" : ""}...`);
      const t2 = Date.now();
      const pentestResults = await runLimited(findings, concurrency, (f) => client.pentest({ findingId: f.id }));
      spin2.succeed(`Pentest complete  ${chalk.dim(`·  ${formatElapsed(t2)}`)}`);
      for (const updated of pentestResults) {
        const i = findings.findIndex((f) => f.id === updated.id);
        if (i >= 0) findings[i] = updated;
      }
    }

    printFindings(findings);

    if (findings.length === 0) {
      console.log(`\n  ${chalk.green("✓")}  ${chalk.bold("No issues found")}\n`);
    } else {
      console.log(`\n  ${findingSummary(findings)}\n`);
    }

    process.exitCode = findings.length > 0 ? 1 : 0;
  });

program
  .command("list")
  .description("List findings")
  .option("--status <status>", "Filter by finding status")
  .option("--severity <severity>", "Filter by severity")
  .action(async (options) => {
    const findings = await new SentinelApiClient().findings({ status: options.status, severity: options.severity });

    if (findings.length === 0) {
      console.log(`\n  ${chalk.green("✓")}  No findings\n`);
      return;
    }

    const counts: Record<string, number> = {};
    for (const f of findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
    const summary = Object.entries(counts).map(([sev, n]) => severityColor(sev)(`${n} ${sev}`)).join("  ·  ");
    console.log(`\n  ${chalk.bold(findings.length)} findings  ·  ${summary}`);

    formatTable(
      ["SEVERITY", "TYPE", "FILE", "TITLE", "ID"],
      findings.map((f) => [
        f.severity.toUpperCase(),
        f.vuln_type,
        f.file ? `${f.file}${f.line_start ? `:${f.line_start}` : ""}` : "—",
        f.title.length > 48 ? f.title.slice(0, 45) + "..." : f.title,
        f.id.slice(0, 8),
      ])
    );
    console.log();
  });

program
  .command("pull")
  .description("Fetch remediation context for a finding")
  .argument("<id>", "Finding ID")
  .action(async (id: string) => {
    const result = await new SentinelApiClient().pull(id);
    const f = result.finding;
    const loc = f.file ? `${f.file}${f.line_start ? `:${f.line_start}` : ""}` : null;

    console.log(`\n  ${severityBadge(f.severity)}  ${chalk.bold(f.title)}`);
    if (loc) console.log(`     ${chalk.dim(loc)}`);
    console.log(`     ${chalk.dim(f.vuln_type)}  ·  ${chalk.dim(f.id)}`);
    console.log();
    console.log(`  ${f.description}`);

    if (result.remediation_plan.length > 0) {
      console.log(`\n  ${chalk.bold("Remediation")}`);
      for (let i = 0; i < result.remediation_plan.length; i++) {
        console.log(`    ${chalk.dim(`${i + 1}.`)} ${result.remediation_plan[i]}`);
      }
    }

    if (result.node) {
      const node = result.node as Record<string, unknown>;
      console.log(`\n  ${chalk.bold("Graph node")}`);
      console.log(`    ${chalk.dim(String(node.kind ?? ""))}  ${chalk.bold(String(node.name ?? ""))}  ${chalk.dim(node.file ? `${node.file}${node.line_start ? `:${node.line_start}` : ""}` : "")}`);
      if (node.is_entry_point) console.log(`    ${chalk.yellow("entry point")}`);
      if (node.is_sink) console.log(`    ${chalk.red("sink")}`);
      if (node.intent) console.log(`    ${chalk.dim("intent:")} ${String(node.intent)}`);
    }
    console.log();
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
        process.stdin.on("data", (chunk) => { data += chunk; });
        process.stdin.on("end", () => resolve(data));
      });
    }
    if (!content.trim()) throw new Error("Provide a plan file, inline plan text, or stdin content.");

    const spin = new Spinner("Reviewing plan for security issues...");
    const t = Date.now();
    const result = await new SentinelApiClient().plan(content, Boolean(options.withRetry));
    spin.succeed(`Review complete  ${chalk.dim(`·  ${formatElapsed(t)}`)}  ·  ${findingSummary(result.findings)}`);

    printFindings(result.findings);

    if (result.findings.length === 0) {
      console.log(`\n  ${chalk.green("✓")}  ${chalk.bold("No issues found")}\n`);
    } else {
      console.log(`\n  ${findingSummary(result.findings)}\n`);
    }

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
    const target = parsePentestTarget(targetParts);
    const spin = new Spinner("Running pentest...");
    const finding = await new SentinelApiClient().pentest(target, options.sanitizerOutput ?? "", options.behavioralProof, options.proofDetail);
    spin.stop();

    if (finding.confirmed) {
      console.log(`  ${chalk.green("✓")}  ${chalk.bold.green("Confirmed")}  ${severityBadge(finding.severity)}  ${finding.title}`);
      console.log(`     ${chalk.dim(finding.id)}`);
      if (finding.evidence) console.log(`\n     ${chalk.dim("Evidence:")} ${finding.evidence}`);
    } else {
      console.log(`  ${chalk.dim("○")}  ${chalk.bold("Not confirmed")}  ${severityBadge(finding.severity)}  ${finding.title}`);
      console.log(`     ${chalk.dim(finding.id)}`);
    }
    console.log();
  });

const suppress = program.command("suppress").description("Suppress or remove suppressions");
suppress
  .argument("<id>", "Finding ID")
  .requiredOption("--reason <reason>", "Suppression reason")
  .action(async (id: string, options) => {
    const finding = await new SentinelApiClient().suppress(id, options.reason);
    console.log(`\n  ${chalk.green("✓")}  Finding ${chalk.dim(id.slice(0, 8))} suppressed  ${chalk.dim(`·  ${finding.status}`)}\n`);
  });
suppress
  .command("remove")
  .argument("<id>", "Finding ID")
  .requiredOption("--reason <reason>", "Unsuppression reason")
  .action(async (id: string, options) => {
    const finding = await new SentinelApiClient().unsuppress(id, options.reason);
    console.log(`\n  ${chalk.green("✓")}  Suppression removed  ${chalk.dim(`·  ${finding.status}`)}\n`);
  });
suppress
  .command("approve")
  .argument("<id>", "Finding ID")
  .requiredOption("--reason <reason>", "Approval reason")
  .action(async (id: string, options) => {
    const finding = await new SentinelApiClient().approveSuppression(id, options.reason);
    console.log(`\n  ${chalk.green("✓")}  Suppression approved  ${chalk.dim(`·  ${finding.status}`)}\n`);
  });
suppress
  .command("reject")
  .argument("<id>", "Finding ID")
  .requiredOption("--reason <reason>", "Rejection reason")
  .action(async (id: string, options) => {
    const finding = await new SentinelApiClient().rejectSuppression(id, options.reason);
    console.log(`\n  ${chalk.green("✓")}  Suppression rejected  ${chalk.dim(`·  ${finding.status}`)}\n`);
  });

const runs = program.command("runs").description("Manage run traces");
runs
  .command("list")
  .action(async () => {
    const rows = await new SentinelApiClient().runs();
    if (rows.length === 0) {
      console.log(`\n  ${chalk.dim("No runs yet.")}\n`);
      return;
    }
    console.log(`\n  ${chalk.bold(rows.length)} run${rows.length !== 1 ? "s" : ""}`);
    formatTable(
      ["ID", "KIND", "STATUS", "FINDINGS", "TOKENS", "MODEL", "CREATED"],
      rows.map((r) => [
        r.id.slice(0, 8),
        r.kind,
        r.status === "completed" ? chalk.green(r.status) : r.status === "failed" ? chalk.red(r.status) : chalk.yellow(r.status),
        String(r.finding_count),
        r.token_spend ? r.token_spend.toLocaleString() : "—",
        r.model_used ?? "—",
        fmtDate(r.created_at),
      ])
    );
    console.log();
  });
runs
  .command("show")
  .argument("<id>", "Run ID")
  .action(async (id: string) => {
    const run = await new SentinelApiClient().run(id);
    const trace = await new SentinelApiClient().trace(id);

    console.log(`\n  ${chalk.bold(`Run ${run.id.slice(0, 8)}`)}  ${chalk.dim(`·  ${run.kind}  ·  ${run.status}`)}`);
    if (run.completed_at) {
      const dur = (new Date(run.completed_at).getTime() - new Date(run.created_at).getTime()) / 1000;
      console.log(`  ${chalk.dim(`Created: ${fmtDate(run.created_at)}  ·  Duration: ${dur.toFixed(1)}s`)}`);
    }
    if (run.model_used) console.log(`  ${chalk.dim(`Model: ${run.model_used}`)}`);

    const summary = summarizeTokens(trace);
    if (summary.totalInput + summary.totalOutput > 0) {
      console.log();
      formatTable(
        ["Component", "Input", "Output", "Total"],
        [
          ...summary.rows.map((r) => [r.component, r.input.toLocaleString(), r.output.toLocaleString(), (r.input + r.output).toLocaleString()]),
          ["Total", summary.totalInput.toLocaleString(), summary.totalOutput.toLocaleString(), (summary.totalInput + summary.totalOutput).toLocaleString()],
        ]
      );
    }
    console.log();
  });
runs
  .command("watch")
  .argument("<id>", "Run ID")
  .action(async (id: string) => {
    console.log(`\n  ${chalk.dim(`Watching run ${id.slice(0, 8)}...`)}\n`);
    const client = new SentinelApiClient();
    for await (const event of client.runEvents(id)) {
      try {
        const parsed = JSON.parse(event) as { kind?: string; status?: string; message?: string; [key: string]: unknown };
        const icon = parsed.kind?.includes("error") || parsed.status === "failed" ? chalk.red("✗") : chalk.dim("·");
        const text = parsed.message ?? parsed.kind ?? event;
        console.log(`  ${icon}  ${chalk.dim(text)}`);
        if (parsed.kind === "complete" || parsed.status === "failed" || parsed.status === "cancelled") break;
      } catch {
        console.log(`  ${chalk.dim("·")}  ${chalk.dim(event)}`);
      }
    }
    console.log();
  });
runs
  .command("cancel")
  .argument("<id>", "Run ID")
  .action(async (id: string) => {
    const run = await new SentinelApiClient().cancelRun(id);
    console.log(`\n  ${chalk.green("✓")}  Run ${chalk.dim(run.id.slice(0, 8))} cancelled\n`);
  });

const config = program.command("config").description("Manage local Sentinel config");
config.command("show").action(() => {
  const cfg = loadConfig();
  console.log(`\n  ${chalk.bold("Configuration")}  ${chalk.dim(`·  ${cfg.repoName}`)}\n`);
  console.log(`  Provider:  ${chalk.bold(cfg.provider === "local" ? "local (Ollama)" : cfg.provider)}`);
  console.log(`  Model:     ${chalk.bold(cfg.model)}`);
  console.log(`  API URL:   ${chalk.bold(cfg.apiUrl)}`);
  if (cfg.boot) console.log(`  Boot:      ${chalk.dim(cfg.boot)}`);
  if (cfg.healthcheck) console.log(`  Health:    ${chalk.dim(cfg.healthcheck)}`);
  console.log();
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
      const spin = new Spinner("Storing API key on server...");
      await client.patchConfig({ api_key: value });
      spin.succeed("API key stored on server");
      return;
    }

    const serverSyncKeys = new Set(["provider", "model", "api_endpoint"]);
    const allowed = new Set(["apiUrl", "repoName", "provider", "model", "boot", "healthcheck", "api_endpoint", "repo_id"]);

    if (key.startsWith("firecracker.")) {
      setFirecrackerConfigValue(current, key.slice("firecracker.".length), value);
      writeConfig(ConfigSchema.parse(current), root);
      console.log(`\n  ${chalk.green("✓")}  ${chalk.bold(key)} set\n`);
      return;
    }
    if (!allowed.has(key)) throw new Error(`Unsupported config key ${key}`);

    current[key] = value;
    writeConfig(ConfigSchema.parse(current), root);

    if (serverSyncKeys.has(key)) {
      const patch: Record<string, string | null> = {};
      patch[key] = value;
      const spin = new Spinner(`Syncing ${key} to server...`);
      await client.patchConfig(patch as { provider?: string; model?: string; api_endpoint?: string | null });
      spin.succeed(`${chalk.bold(key)} set  ${chalk.dim("·  synced to server")}`);
    } else {
      console.log(`\n  ${chalk.green("✓")}  ${chalk.bold(key)} set\n`);
    }
  });

// ── Bootstrap ─────────────────────────────────────────────────────────────────

program.parseAsync().catch(die);

// ── Utilities ─────────────────────────────────────────────────────────────────

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
    } catch { continue; }
  }
  const rows = Array.from(totals.entries()).map(([component, counts]) => ({ component, input: counts.input, output: counts.output }));
  return { rows, totalInput: rows.reduce((s, r) => s + r.input, 0), totalOutput: rows.reduce((s, r) => s + r.output, 0) };
}

function absoluteUrl(apiUrl: string, pathOrUrl: string): string {
  return new URL(pathOrUrl, apiUrl).toString();
}

async function runLimited<T, R>(items: T[], concurrency: number, task: (item: T) => Promise<R>): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let nextIndex = 0;
  const workers = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (nextIndex < items.length) {
      const index = nextIndex++;
      results[index] = await task(items[index]);
    }
  });
  await Promise.all(workers);
  return results;
}

function parsePositiveInt(value: string, label: string): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) throw new Error(`${label} must be a positive integer`);
  return parsed;
}

function parsePentestTarget(parts: string[]): { findingId?: string; description?: string } {
  const target = parts.join(" ").trim();
  if (!target) return {};
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(target)) return { findingId: target };
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
  } else if (["kernel_image","rootfs_image","api_socket","firecracker_bin","boot_args","network_interface_id","host_dev_name","guest_mac"].includes(key)) {
    current[key] = value;
  } else {
    throw new Error(`Unsupported firecracker config key ${key}`);
  }
  config.firecracker = current;
}
