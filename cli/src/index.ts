#!/usr/bin/env node
import { readFileSync, existsSync } from "node:fs";
import { basename, join } from "node:path";
import chalk from "chalk";
import { Command } from "commander";

import { SentinelApiClient } from "./api/client.js";
import { ConfigSchema, configPath, findRepoRoot, loadConfig, writeConfig } from "./config/sentinel.config.js";
import { currentDiff, lsFiles } from "./diff/git.js";

const program = new Command();

program.name("sentinel").description("Cloud-backed application security scanner").version("0.1.0");

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
  .action(async (paths: string[], options) => {
    const diff = currentDiff({ staged: options.staged, base: options.base, paths });
    const runContext = process.env.CI ? "ci" : "local";
    const result = await new SentinelApiClient().source(diff, runContext);
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
    console.log(await new SentinelApiClient().trace(id));
  });

program
  .command("config")
  .description("Show current config")
  .argument("[action]", "show")
  .action((action = "show") => {
    if (action !== "show") throw new Error("Only `sentinel config show` is currently supported.");
    console.log(JSON.stringify(loadConfig(), null, 2));
  });

program.parseAsync().catch((error) => {
  console.error(chalk.red(`Error: ${error.message}`));
  process.exitCode = 2;
});
