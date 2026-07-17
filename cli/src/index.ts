#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { basename, join, resolve as resolvePath } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as sleep } from "node:timers/promises";
import chalk from "chalk";
import { Command } from "commander";

import { SentinelApiClient, type Finding } from "./api/client.js";
import { clearApiKey, readApiKey, readLlmApiKey, writeApiKey, writeCredential, writeLlmApiKey } from "./auth/keychain.js";
import { writeWorkerConn } from "./backend/ensure.js";
import { ConfigSchema, configPath, findRepoRoot, loadConfig, validateConfigForScan, writeConfig } from "./config/sentinel.config.js";
import { currentDiff } from "./diff/git.js";
import { ensureBackend, startBackend, stopBackend, backendStatus, isHealthy, resolveVenvPython } from "./backend/ensure.js";
import { runLocalInit, runLocalPentest, runLocalPlanReview, runLocalSourceScan } from "./engine/localEngine.js";
import { printAdapterWarnings } from "./output/adapterWarnings.js";

const program = new Command();

/** The current git branch, or null if it can't be determined (e.g. detached HEAD). */
function currentBranch(): string | null {
  const r = spawnSync("git", ["rev-parse", "--abbrev-ref", "HEAD"], { encoding: "utf8" });
  if (r.status !== 0) return null;
  const branch = r.stdout.trim();
  return branch && branch !== "HEAD" ? branch : null;
}

program.name("sentinel").description("LLM-powered application security scanner — scans run locally, only the code graph and findings sync to the cloud").version("0.1.1");

const auth = program.command("auth").description("Manage Sentinel authentication");
auth
  .command("login")
  .description("Authorize this CLI with a browser-based device code")
  .option("--poll-interval <seconds>", "Polling interval while waiting for approval", "2")
  .action(async (options) => {
    const config = loadConfig();
    await ensureBackend(config.apiUrl);
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
        await writeCredential(config, { accessToken: token.access_token, refreshToken: token.refresh_token });
        if (token.database_url) {
          writeWorkerConn({ databaseUrl: token.database_url, accountId: token.account_id });
        }
        console.log(`logged in as ${token.user_id} for account ${token.account_id}`);
        return;
      }
      await sleep(Math.min(pollIntervalMs, Math.max(0, deadline - Date.now())));
    }
    throw new Error("device code expired before approval");
  });

auth
  .command("logout")
  .description("Log out and revoke the stored credential")
  .action(async () => {
    const config = loadConfig();
    try {
      await ensureBackend(config.apiUrl);
      await new SentinelApiClient(config).logout();
    } catch {
      // Best-effort server-side revocation — always clear the local credential.
    }
    await clearApiKey(config);
    console.log("logged out");
  });

auth
  .command("whoami")
  .description("Show the currently authenticated user")
  .action(async () => {
    const config = loadConfig();
    await ensureBackend(config.apiUrl);
    const identity = await new SentinelApiClient(config).whoami();
    console.log(`${identity.email}  (${identity.role}) — account ${identity.account_name}`);
  });

program
  .command("init")
  .description("Initialize Sentinel for this repository")
  .option("--api-url <url>", "Sentinel API URL", "https://sentinel-steel-xi.vercel.app")
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
    await ensureBackend(config.apiUrl);
    // The codebase is parsed into a graph entirely on this machine; only the
    // resulting nodes/edges (pointers + short labels, never source text) are
    // sent to the cloud. See non-code/README.md's local-AI-calls model.
    const [apiToken, llmApiKey] = await Promise.all([readApiKey(config), readLlmApiKey(config)]);
    const result = await runLocalInit({ config, repoDir: root, apiToken, llmApiKey });
    console.log(`initialized ${repoName}: ${result.nodes} graph nodes, ${result.edges} edges pushed`);
    if (result.local_trace_path) console.log(`trace saved locally: ${result.local_trace_path}`);
  });

program
  .command("source")
  .description("Scan the current git diff — locally. Source and diffs never leave this machine.")
  .argument("[paths...]", "Optional paths to scope the diff")
  .option("--staged", "Scan staged changes only")
  .option("--base <ref>", "Diff against this base ref")
  .action(async (paths: string[], options) => {
    const config = loadConfig();
    validateConfigForScan(config);
    await ensureBackend(config.apiUrl);
    const root = findRepoRoot();
    const diff = currentDiff({ staged: options.staged, base: options.base, paths });
    if (!diff.trim()) {
      console.log("no changes to scan");
      process.exitCode = 0;
      return;
    }
    const runContext = process.env.CI ? "ci" : "local";
    const [apiToken, llmApiKey] = await Promise.all([readApiKey(config), readLlmApiKey(config)]);

    const { result, exitCode } = await runLocalSourceScan({
      config,
      repoDir: root,
      diff,
      baseRef: options.base,
      runContext,
      apiToken,
      llmApiKey,
    });
    for (const finding of result.findings) {
      console.log(`${chalk.red(finding.severity.toUpperCase())} ${finding.vuln_type} ${finding.fingerprint.slice(0, 8)}`);
      console.log(`  ${finding.title}`);
      if (finding.remediation) console.log(`  fix: ${finding.remediation}`);
    }
    // AUDIT.md §6 W4 P5.4: surface files no framework adapter matched (stderr).
    printAdapterWarnings(result.adapter_unmatched_files);
    console.log(`${result.finding_count} finding(s) · pushed ${result.graph_nodes_pushed} graph node(s), ${result.graph_edges_pushed} edge(s)`);
    if (result.local_trace_path) console.log(`trace saved locally: ${result.local_trace_path}`);
    process.exitCode = exitCode;
  });

program
  .command("scan")
  .description("Run source scan locally, then run a local pentest for each pushed finding unless skipped")
  .argument("[paths...]", "Optional paths to scope the diff")
  .option("--staged", "Scan staged changes only")
  .option("--base <ref>", "Diff against this base ref")
  .option("--no-pentest", "Skip running local pentests")
  .option("--pentest-concurrency <count>", "Maximum concurrent local pentest runs", "4")
  .option("--no-sandbox", "Run pentests without a Docker/gVisor sandbox (reduced isolation)")
  .action(async (paths: string[], options) => {
    const config = loadConfig();
    validateConfigForScan(config);
    await ensureBackend(config.apiUrl);
    const root = findRepoRoot();
    const diff = currentDiff({ staged: options.staged, base: options.base, paths });
    const runContext = process.env.CI ? "ci" : "local";
    const [apiToken, llmApiKey] = await Promise.all([readApiKey(config), readLlmApiKey(config)]);

    if (!diff.trim()) {
      console.log("no changes to scan");
      process.exitCode = 0;
      return;
    }

    const { result, exitCode } = await runLocalSourceScan({
      config,
      repoDir: root,
      diff,
      baseRef: options.base,
      runContext,
      apiToken,
      llmApiKey,
    });
    for (const finding of result.findings) {
      console.log(`${chalk.red(finding.severity.toUpperCase())} ${finding.vuln_type} ${finding.fingerprint.slice(0, 8)}`);
      console.log(`  ${finding.title}`);
    }
    // AUDIT.md §6 W4 P5.4: surface files no framework adapter matched (stderr).
    printAdapterWarnings(result.adapter_unmatched_files);

    const findingIds = result.push.findings?.finding_ids ?? [];
    let pentestFailures = 0;
    if (options.pentest && findingIds.length > 0) {
      // Run one LOCAL pentest per ingested finding id, bounded by
      // --pentest-concurrency (distinct per-run sandbox/egress-proxy). Nothing
      // is enqueued to the cloud — execution is the full local stack.
      const concurrency = parsePositiveInt(options.pentestConcurrency, "pentest concurrency");
      // Isolate each finding's pentest: one failure (e.g. a boot error, or docker
      // missing) must not abort the batch or discard already-completed results.
      const pentested = await runLimited(findingIds, concurrency, async (findingId) => {
        try {
          const r = await runLocalPentest({
            config,
            repoDir: root,
            apiToken,
            llmApiKey,
            findingId,
            repoId: config.repo_id,
            boot: config.boot,
            healthcheck: config.healthcheck,
            egressAllowlist: config.egress_allowlist,
            noSandbox: !options.sandbox,
          });
          return { findingId, result: r };
        } catch (err) {
          return { findingId, error: err instanceof Error ? err.message : String(err) };
        }
      });
      for (const p of pentested) {
        if ("error" in p && p.error !== undefined) {
          pentestFailures += 1;
          console.error(`pentest ${p.findingId}: failed — ${p.error}`);
        } else if (p.result) {
          console.log(`pentest ${p.findingId}: ${p.result.status} confirmed=${p.result.confirmed}`);
        }
      }
      if (pentestFailures > 0) {
        console.error(`${pentestFailures} of ${findingIds.length} pentest(s) failed`);
      }
    } else if (options.pentest && result.findings.length > 0) {
      console.log("(pentest skipped: findings were not pushed to the cloud, so no finding IDs are available — check network/auth)");
    }
    console.log(`scan: ${result.finding_count} finding(s)`);
    if (result.local_trace_path) console.log(`trace saved locally: ${result.local_trace_path}`);
    // Non-zero if the source scan tripped its fail-on threshold OR any pentest failed.
    process.exitCode = exitCode || (pentestFailures > 0 ? 1 : 0);
  });

program
  .command("merge")
  .description("Merge this branch's graph into main (run in CD when a branch lands)")
  .option("--branch <name>", "Branch to merge (defaults to the current git branch)")
  .action(async (options) => {
    const config = loadConfig();
    await ensureBackend(config.apiUrl);
    const branch = options.branch ?? currentBranch();
    if (!branch) {
      console.error("could not determine the branch to merge; pass --branch <name>");
      process.exitCode = 1;
      return;
    }
    const client = new SentinelApiClient(config);
    const result = await client.mergeBranch(config.repoName, branch);
    console.log(
      `merged branch '${branch}' into main: ${result.copied} node/edge change(s), ` +
        `${result.findings_repointed} finding(s) re-pointed${result.had_base ? "" : " (no base — 2-way)"}`
    );
    if (result.conflicts.length > 0) {
      const shown = result.conflicts.slice(0, 10).join(", ");
      const more = result.conflicts.length > 10 ? "…" : "";
      console.log(chalk.yellow(`  ${result.conflicts.length} conflict(s) — branch version kept: ${shown}${more}`));
    }
  });

program
  .command("list")
  .description("List findings")
  .option("--status <status>", "Filter by finding status")
  .option("--severity <severity>", "Filter by severity")
  .action(async (options) => {
    const config = loadConfig();
    await ensureBackend(config.apiUrl);
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
    await ensureBackend(config.apiUrl);
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
    await ensureBackend(config.apiUrl);
    const root = findRepoRoot();
    const [apiToken, llmApiKey] = await Promise.all([readApiKey(config), readLlmApiKey(config)]);
    const { result, exitCode } = await runLocalPlanReview({
      config,
      repoDir: root,
      content,
      withRetry: Boolean(options.withRetry),
      apiToken,
      llmApiKey,
    });
    for (const finding of result.findings) {
      console.log(`${chalk.red(finding.severity.toUpperCase())} ${finding.vuln_type}: ${finding.title}`);
      console.log(`  ${finding.description}`);
      console.log(`  fix: ${finding.remediation}`);
    }
    console.log(`plan review completed with ${result.finding_count} issue(s)`);
    if (result.local_trace_path) console.log(`trace saved locally: ${result.local_trace_path}`);
    process.exitCode = exitCode;
  });

program
  .command("pentest")
  .description("Confirm a finding by attacking the app booted locally under the full gVisor sandbox stack")
  .argument("[target...]", "Finding ID, natural-language target, or empty to auto-select the highest-severity open finding")
  .option("--sanitizer-output <text>", "Sanitizer output")
  .option("--behavioral-proof <kind>", "Behavioral proof kind")
  .option("--proof-detail <text>", "Behavioral proof detail", "")
  .option("--no-sandbox", "Run without a Docker/gVisor sandbox (reduced isolation); default auto-degrades if not found")
  .action(async (targetParts: string[], options) => {
    // Pentest runs the FULL hardened stack (gVisor + egress proxy + canary +
    // broker + attack-safety + oracle) on THIS machine. Source stays local; the
    // Python engine fetches the finding from the cloud and pushes back only the
    // confirmation outcome via POST /findings/{id}/confirm.
    const config = loadConfig();
    validateConfigForScan(config);
    await ensureBackend(config.apiUrl);
    const root = findRepoRoot();
    const [apiToken, llmApiKey] = await Promise.all([readApiKey(config), readLlmApiKey(config)]);
    const client = new SentinelApiClient(config);

    // Resolve the target to a concrete finding id, entirely client-side (D4):
    //   - a bare id is used directly
    //   - a natural-language target is ranked over the open findings
    //   - no target auto-selects the highest-severity open finding
    const target = parsePentestTarget(targetParts);
    let findingId = target.findingId;
    if (!findingId) {
      findingId = (await resolvePentestTargetId(client, target.description)) ?? undefined;
      if (!findingId) {
        console.error(
          target.description
            ? `no open finding matched "${target.description}" — run \`sentinel list\` to see finding ids`
            : "no open findings to pentest — run `sentinel scan` first"
        );
        process.exitCode = 1;
        return;
      }
      console.log(`resolved target -> finding ${findingId}`);
    }

    const result = await runLocalPentest({
      config,
      repoDir: root,
      apiToken,
      llmApiKey,
      findingId,
      repoId: config.repo_id,
      sanitizerOutput: options.sanitizerOutput,
      behavioralProof: options.behavioralProof,
      proofDetail: options.proofDetail,
      boot: config.boot,
      healthcheck: config.healthcheck,
      egressAllowlist: config.egress_allowlist,
      noSandbox: !options.sandbox,
    });
    console.log(`${result.finding_id}\t${result.status}\tconfirmed=${result.confirmed}`);
    if (result.evidence) console.log(result.evidence);
    if (result.local_trace_path) console.log(`trace saved locally: ${result.local_trace_path}`);
  });

const suppress = program.command("suppress").description("Suppress or remove suppressions");
suppress
  .command("add", { isDefault: true })
  .description("Suppress a finding")
  .argument("<id>", "Finding ID")
  .requiredOption("--reason <reason>", "Suppression reason")
  .action(async (id: string, options) => {
    const config = loadConfig();
    await ensureBackend(config.apiUrl);
    const finding = await new SentinelApiClient(config).suppress(id, options.reason);
    console.log(`${finding.id}\t${finding.status}`);
  });
suppress
  .command("remove")
  .description("Remove a suppression")
  .argument("<id>", "Finding ID")
  .requiredOption("--reason <reason>", "Unsuppression reason")
  .action(async (id: string, options) => {
    const config = loadConfig();
    await ensureBackend(config.apiUrl);
    const finding = await new SentinelApiClient(config).unsuppress(id, options.reason);
    console.log(`${finding.id}\t${finding.status}`);
  });
suppress
  .command("approve")
  .description("Approve a pending suppression request")
  .argument("<id>", "Finding ID")
  .requiredOption("--reason <reason>", "Approval reason")
  .action(async (id: string, options) => {
    const config = loadConfig();
    await ensureBackend(config.apiUrl);
    const finding = await new SentinelApiClient(config).approveSuppression(id, options.reason);
    console.log(`${finding.id}\t${finding.status}`);
  });
suppress
  .command("reject")
  .description("Reject a pending suppression request")
  .argument("<id>", "Finding ID")
  .requiredOption("--reason <reason>", "Rejection reason")
  .action(async (id: string, options) => {
    const config = loadConfig();
    await ensureBackend(config.apiUrl);
    const finding = await new SentinelApiClient(config).rejectSuppression(id, options.reason);
    console.log(`${finding.id}\t${finding.status}`);
  });

const runs = program.command("runs").description("Manage run traces");
runs
  .command("list")
  .action(async () => {
    const config = loadConfig();
    await ensureBackend(config.apiUrl);
    const rows = await new SentinelApiClient(config).runs();
    console.log("ID\tKIND\tSTATUS\tFINDINGS\tTOKENS\tMODEL\tCREATED");
    for (const run of rows) {
      console.log(`${run.id}\t${run.kind}\t${run.status}\t${run.finding_count}\t${run.token_spend}\t${run.model_used ?? "n/a"}\t${run.created_at}`);
    }
  });
runs
  .command("show")
  .argument("<id>", "Run ID (a local run ID from `sentinel source/scan/plan/pentest`, or a cloud run ID)")
  .action(async (id: string) => {
    const config = loadConfig();
    const localTracePath = join(homedir(), ".sentinel", "runs", `${id}.jsonl`);
    let trace: string;
    if (existsSync(localTracePath)) {
      // Full local traces (every prompt, every tool call) never leave this
      // machine — the cloud only ever gets a redacted run summary.
      trace = readFileSync(localTracePath, "utf8");
      console.log(`(reading full trace from local file: ${localTracePath})\n`);
    } else {
      await ensureBackend(config.apiUrl);
      trace = await new SentinelApiClient(config).trace(id);
      console.log("(no local trace found for this ID — showing the cloud's redacted run summary)\n");
    }
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
    await ensureBackend(config.apiUrl);
    const client = new SentinelApiClient(config);
    await watchRunToTerminal(client, id);
  });
runs
  .command("cancel")
  .argument("<id>", "Run ID")
  .action(async (id: string) => {
    const config = loadConfig();
    await ensureBackend(config.apiUrl);
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
      // The LLM provider key is used locally by the scan engine and never
      // sent to the Sentinel cloud — stored in the system keychain (or the
      // ~/.sentinel fallback), same mechanism as the Sentinel auth token.
      await writeLlmApiKey(loadConfig(root), value);
      console.log("api-key stored locally (never sent to the Sentinel cloud)");
      return;
    }

    const serverSyncKeys = new Set(["provider", "model", "api_endpoint"]);
    // AUDIT.md §3 D1 — these live on the cloud Repo (pentest reachability
    // config) and are synced via PATCH /repos/{id}/pentest-config. `boot`,
    // `healthcheck`, and `egress_allowlist` double as repo pentest config now
    // that pentest runs on the cloud worker (§3 D4), not this machine.
    const pentestConfigKeys = new Set([
      "staging_base_url", "pentest_mode", "healthcheck_path", "boot", "healthcheck", "egress_allowlist",
    ]);
    const allowed = new Set([
      "apiUrl", "repoName", "provider", "model", "boot", "healthcheck", "api_endpoint", "repo_id",
      "staging_base_url", "pentest_mode", "healthcheck_path", "egress_allowlist",
    ]);

    if (!allowed.has(key)) {
      throw new Error(`Unsupported config key ${key}`);
    }
    // egress_allowlist is a comma-separated list locally; everything else is a scalar.
    const parsedValue: unknown = key === "egress_allowlist" ? value.split(",").map((s) => s.trim()).filter(Boolean) : value;
    current[key] = parsedValue;
    const parsedConfig = ConfigSchema.parse(current);
    writeConfig(parsedConfig, root);

    if (serverSyncKeys.has(key)) {
      await ensureBackend(loadConfig(root).apiUrl);
      const patch: Record<string, string | null> = {};
      patch[key] = value;
      await client.patchConfig(patch as { provider?: string; model?: string; api_endpoint?: string | null });
      console.log(`set ${key} (local + server)`);
    } else if (pentestConfigKeys.has(key)) {
      // Sync pentest reachability config to the cloud Repo (P1.4). Requires
      // repo_id in local config — the cloud is the source of truth the worker
      // reads at pentest time (§3 D1).
      const repoId = parsedConfig.repo_id;
      if (!repoId) {
        console.log(`set ${key} (local only — set 'repo_id' in sentinel.config.json to sync pentest config to the cloud)`);
        return;
      }
      await ensureBackend(loadConfig(root).apiUrl);
      const patch: Record<string, unknown> = { [key]: parsedValue };
      // Also sync the structured gVisor sandbox config (sandbox/egress/secrets/
      // canary/attack_safety) edited in the JSON, so the worker sees it.
      const blob = buildPentestConfigBlob(current);
      if (blob) patch.pentest_config = blob;
      await client.patchPentestConfig(repoId, patch);
      console.log(`set ${key} (local + cloud repo pentest config)`);
    } else {
      console.log(`set ${key}`);
    }
  });

// AUDIT.md P4.1 — pre-flight checks. Exits non-zero with actionable messages
// when something the CLI needs is missing or misconfigured (§5 Gate 4).
program
  .command("doctor")
  .description("Run pre-flight checks: git repo, config, cloud health, auth, local engine, LLM key, pentest sandbox (docker + gVisor), pentest config")
  .action(async () => {
    const checks: Array<{ ok: boolean; warn?: boolean; label: string; detail?: string }> = [];
    const record = (ok: boolean, label: string, detail?: string, warn = false) => checks.push({ ok, warn, label, detail });

    // 1. git repo
    const root = findRepoRoot();
    const inGitRepo = existsSync(join(root, ".git"));
    record(inGitRepo, "git repository", inGitRepo ? root : "no .git found — run `sentinel` from inside a git repo");

    // 2. config
    let config: ReturnType<typeof loadConfig> | undefined;
    try {
      config = loadConfig(root);
      const hasConfigFile = existsSync(configPath(root));
      record(true, "config", hasConfigFile ? configPath(root) : "using defaults (no sentinel.config.json — run `sentinel init`)", !hasConfigFile);
    } catch (error) {
      record(false, "config", `invalid config: ${error instanceof Error ? error.message : String(error)}`);
    }

    const apiUrl = config?.apiUrl ?? "https://sentinel-steel-xi.vercel.app";

    // 3. cloud health
    const healthy = await isHealthy(apiUrl, 3000);
    record(healthy, "cloud API reachable", healthy ? apiUrl : `${apiUrl} not reachable — start it with 'sentinel up' or check apiUrl`);

    // 4. auth
    if (config) {
      const token = await readApiKey(config);
      record(Boolean(token), "authenticated", token ? "credential present" : "no credential — run `sentinel auth login`");
    }

    // 5. local engine (SAST runs here — §1)
    const pythonBin = resolveVenvPython();
    let engineOk = false;
    let engineDetail = "";
    try {
      const proc = spawnSync(pythonBin, ["-c", "import sentinel_worker.local_cli"], { encoding: "utf8" });
      engineOk = proc.status === 0;
      engineDetail = engineOk
        ? `${pythonBin}`
        : `cannot import sentinel_worker (${pythonBin}) — install it with 'pip install ./worker' or set SENTINEL_PYTHON`;
    } catch (error) {
      engineDetail = `local engine check failed: ${error instanceof Error ? error.message : String(error)}`;
    }
    record(engineOk, "local analysis engine", engineDetail);

    // 6. LLM key (SAST uses a local key — §3 D2; never sent to the cloud)
    if (config) {
      const llmKey = await readLlmApiKey(config);
      const localProvider = config.provider === "local" || config.provider === "mock";
      const keyOk = Boolean(llmKey) || localProvider;
      record(
        keyOk,
        "LLM API key (local SAST)",
        keyOk
          ? (llmKey ? "key present (local keychain)" : `provider '${config.provider}' needs no key`)
          : "no LLM key — run `sentinel config set api-key <key>`",
        !keyOk
      );

      // 7. pentest config — the local pentest needs a target: either a boot
      // command (the app is booted locally under the sandbox) or a reachable
      // staging_base_url. Warn only — SAST works without pentest configured.
      const hasPentestConfig = Boolean(config.boot) || Boolean(config.staging_base_url) || config.pentest_mode === "local_worker";
      record(
        hasPentestConfig,
        "pentest config",
        hasPentestConfig
          ? `mode=${config.pentest_mode ?? "staging"}${config.boot ? ` boot set` : ""}${config.staging_base_url ? ` url=${config.staging_base_url}` : ""}`
          : "no boot / staging_base_url — `sentinel pentest` will have no target. Set one with `sentinel config set boot \"<cmd>\"` or `sentinel config set staging_base_url <url>`",
        true // pentest config is a warning, not a hard failure — SAST still works without it
      );
    }

    // 8. pentest sandbox — a real local pentest boots the target under gVisor
    // (runsc) via docker. Both are advisory: SAST never needs them, but
    // `sentinel pentest` fails loudly without docker, and drops to runc (a
    // weaker isolation boundary) without runsc.
    let dockerOk = false;
    try {
      const proc = spawnSync("docker", ["version", "--format", "{{.Server.Version}}"], { encoding: "utf8" });
      dockerOk = proc.status === 0 && Boolean((proc.stdout || "").trim());
      record(
        dockerOk,
        "docker (pentest sandbox)",
        dockerOk
          ? `server ${(proc.stdout || "").trim()}`
          : "docker not available — `sentinel pentest` requires it to boot the target sandbox (install Docker Desktop). SAST is unaffected.",
        !dockerOk // advisory: SAST works without it
      );
    } catch (error) {
      record(false, "docker (pentest sandbox)", `docker check failed: ${error instanceof Error ? error.message : String(error)}`, true);
    }

    if (dockerOk) {
      let runscOk = false;
      try {
        const proc = spawnSync("docker", ["info", "--format", "{{json .Runtimes}}"], { encoding: "utf8" });
        runscOk = proc.status === 0 && (proc.stdout || "").includes("runsc");
        record(
          runscOk,
          "gVisor / runsc (pentest isolation)",
          runscOk
            ? "runsc runtime registered with docker"
            : "runsc not registered — the pentest falls back to runc (weaker isolation). Install gVisor and add it to /etc/docker/daemon.json for full hardening.",
          !runscOk // advisory: a runc fallback still runs the pentest
        );
      } catch (error) {
        record(false, "gVisor / runsc (pentest isolation)", `runsc check failed: ${error instanceof Error ? error.message : String(error)}`, true);
      }
    }

    let hardFailures = 0;
    for (const c of checks) {
      // A check flagged `warn` is advisory (never a hard failure); render it
      // yellow whether or not it passed. Only ok && !warn is green.
      const status = c.warn ? chalk.yellow("warn") : c.ok ? chalk.green("ok  ") : chalk.red("FAIL");
      console.log(`[${status}] ${c.label}${c.detail ? `: ${c.detail}` : ""}`);
      if (!c.ok && !c.warn) hardFailures += 1;
    }
    if (hardFailures > 0) {
      console.log(chalk.red(`\n${hardFailures} check(s) failed.`));
      process.exitCode = 1;
    } else {
      console.log(chalk.green("\nAll required checks passed."));
    }
  });

// Backend lifecycle commands
program
  .command("up")
  .description("Start the local Sentinel backend (results-only API)")
  .action(async () => {
    const config = loadConfig();
    await startBackend(config.apiUrl);
    console.log("Sentinel backend started.");
  });

program
  .command("down")
  .description("Stop the Sentinel backend")
  .action(async () => {
    await stopBackend();
    console.log("Sentinel backend stopped.");
  });

program
  .command("status")
  .description("Show Sentinel backend status")
  .action(async () => {
    const config = loadConfig();
    const s = await backendStatus(config.apiUrl);
    console.log(`API:     ${s.api}`);
    console.log(`Healthy: ${s.healthy ? "yes" : "no"}`);
  });

// Only run the CLI when invoked directly (not when imported, e.g. by tests that
// exercise helpers like resolvePentestTargetId).
const isMain = process.argv[1] !== undefined && fileURLToPath(import.meta.url) === resolvePath(process.argv[1]);
if (isMain) {
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
}

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

/** Stream a run's trace to stdout until it reaches a terminal state. */
async function watchRunToTerminal(client: SentinelApiClient, runId: string): Promise<void> {
  for await (const event of client.runEvents(runId)) {
    console.log(event);
    try {
      const parsed = JSON.parse(event) as { kind?: string; status?: string };
      if (parsed.kind === "run.completed" || parsed.kind === "complete" || parsed.status === "failed" || parsed.status === "cancelled") break;
    } catch {
      // Non-JSON trace lines are still useful to display.
    }
  }
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

export function parsePentestTarget(parts: string[]): { findingId?: string; description?: string } {
  const target = parts.join(" ").trim();
  if (!target) return {};
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(target)) {
    return { findingId: target };
  }
  return { description: target };
}

// Highest first. Anything unknown ranks below `info`.
const PENTEST_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];
function severityRank(severity: string): number {
  const idx = PENTEST_SEVERITY_ORDER.indexOf((severity ?? "").toLowerCase());
  return idx === -1 ? PENTEST_SEVERITY_ORDER.length : idx;
}

/**
 * Resolve a pentest target to a finding id entirely client-side (plan D4). Only
 * open findings are considered. With a description, findings are ranked by
 * term-overlap of the description against title/vuln_type/file, tie-broken by
 * severity. With no description, the highest-severity open finding wins.
 * Returns null when there is nothing to run against.
 */
export async function resolvePentestTargetId(
  client: SentinelApiClient,
  description?: string
): Promise<string | null> {
  const open = await client.findings({ status: "open" });
  if (open.length === 0) return null;

  const bySeverity = (a: Finding, b: Finding) => severityRank(a.severity) - severityRank(b.severity);

  if (!description || !description.trim()) {
    // No description — take the single highest-severity open finding.
    return [...open].sort(bySeverity)[0].id;
  }

  const terms = description
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((t) => t.length > 2);

  const scored = open.map((f) => {
    const haystack = `${f.title ?? ""} ${f.vuln_type ?? ""} ${f.file ?? ""}`.toLowerCase();
    const overlap = terms.reduce((n, term) => (haystack.includes(term) ? n + 1 : n), 0);
    return { finding: f, overlap };
  });

  // Rank by term overlap first, then severity as a tie-break.
  scored.sort((a, b) => (b.overlap - a.overlap) || bySeverity(a.finding, b.finding));
  const best = scored[0];
  // Nothing matched any term — fall back to the highest-severity open finding.
  if (best.overlap === 0) return [...open].sort(bySeverity)[0].id;
  return best.finding.id;
}

// The structured gVisor sandbox blocks (sandbox/egress/secrets/canary/
// attack_safety) are edited directly in sentinel.config.json and synced to the
// cloud Repo as one `pentest_config` object the worker reads at pentest time.
export function buildPentestConfigBlob(config: Record<string, unknown>): Record<string, unknown> | undefined {
  const blob: Record<string, unknown> = {};
  for (const key of ["sandbox", "egress", "secrets", "canary", "attack_safety"]) {
    if (config[key] !== undefined) blob[key] = config[key];
  }
  return Object.keys(blob).length > 0 ? blob : undefined;
}
