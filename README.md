<div align="center">

<!-- TODO: add ./assets/logo.png -->
<img src="./assets/logo.png" alt="Sentinel" width="120" />

# Sentinel

*AI-powered attack surface monitoring, dependency risk scoring, and authorization flaw detection — in one pipeline.*

[![CI](https://img.shields.io/github/actions/workflow/status/angadjosan/sentinel/ci.yml?label=CI)](https://github.com/angadjosan/sentinel/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/angadjosan/sentinel)](./LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://pypi.org/project/sentinel-sec/)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)](https://github.com/angadjosan/sentinel/pulls)

</div>

**Get started in 30 seconds:**

```bash
pip install sentinel-sec
sentinel scan --repo https://github.com/your-org/your-repo --domain your-app.com
```

Then open the dashboard: run `sentinel dashboard` and navigate to http://localhost:4000

---

<div align="center">

<!-- TODO: record terminal GIF and save to ./assets/demo-cli.gif -->
![Sentinel CLI scan](./assets/demo-cli.gif)

*CLI scan output — attack surface, deps, and auth flaws in under 60 seconds.*

<!-- TODO: screenshot the dashboard and save to ./assets/demo-dashboard.png -->
![Sentinel dashboard](./assets/demo-dashboard.png)

*Web dashboard — unified findings triage across all three scan stages.*

</div>

---

## Contents

- [Why Sentinel](#why-sentinel)
- [How It Works](#how-it-works)
- [Features](#features)
- [CLI Reference](#cli-reference)
- [Dashboard](#dashboard)
- [Quickstart](#quickstart)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [Threat Model](#threat-model)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Why Sentinel

As AI writes more code faster, security teams can't keep up with manual review. Traditional SAST tools catch syntax-level bugs but miss logic flaws like broken access control — the kind that let an attacker read another user's data by changing a single ID in a URL. The volume of code is outpacing the capacity to reason about it safely.

The insight behind Sentinel is that attack surface, dependency risk, and authorization logic flaws are three angles on the same question: *what can an attacker actually reach and exploit?* Most tools answer only one. Dependency scanners flag thousands of CVEs without knowing whether the vulnerable code is even reachable. Attack surface tools have no idea what the codebase looks like. Code reviewers check auth patterns file by file, without tracing the full middleware chain. Sentinel runs all three in one pipeline and gives you a unified view.

Sentinel is an open-source tool for small engineering teams, individual security researchers, and OSS maintainers who want serious coverage without an enterprise contract. It runs locally, deploys to your own infra, and sends nothing anywhere you haven't explicitly configured.

---

## How It Works

Sentinel is a three-stage pipeline — each stage answers a different question about what an attacker could reach and exploit.

| Stage | What it does | Key output |
|---|---|---|
| 1. Attack Surface | Enumerates subdomains, open ports, TLS config, and dangling DNS for the target domain | List of exposed endpoints + misconfig warnings |
| 2. Dependency Risk | Scores every package in the repo by reachability + CVE severity + patch cadence + transitive exposure | Risk-ranked dependency report |
| 3. Auth Review | LLM reviews new code for API routes missing auth middleware, IDOR patterns, and privilege escalation paths | Annotated findings with severity and CWE ID |

*All three stages share a unified findings format so you can triage everything in the CLI output or the web dashboard.*

---

## Features

- **Attack surface enumeration** — uses Subfinder and Shodan to map what's actually exposed on the internet for a given domain.
- **Reachability-aware dep scoring** — checks whether vulnerable functions in dependencies are actually called in your code, not just present.
- **AI authorization auditing** — uses an LLM to reason about whether new API routes are gated by your existing auth middleware.
- **Unified findings output** — all results share a single JSON schema so they can be piped into Slack, GitHub Issues, or your SIEM.
- **Web dashboard** — local browser UI for triaging findings, filtering by severity, and marking issues as resolved or false positive.
- **GitHub Actions native** — drop-in workflow file scans every PR before it merges.
- **Self-hostable** — no data leaves your environment; bring your own LLM API key.

---

## CLI Reference

All Sentinel functionality is accessible via the `sentinel` CLI.

### `sentinel scan`

Runs a full scan (all three stages) against a repo and domain.

```bash
sentinel scan [flags]
```

| Flag | Type | Default | Description |
|---|---|---|---|
| `--repo` | string | — | GitHub repo URL to scan (required) |
| `--domain` | string | — | Target domain for attack surface enumeration (required) |
| `--stages` | string | `all` | Comma-separated stages to run: `surface,deps,auth` or `all` |
| `--config` | string | `./sentinel.yml` | Path to config file |
| `--output` | string | `./sentinel-report` | Directory to write findings to |
| `--format` | string | `json` | Output format: `json`, `html`, `markdown` |
| `--fail-on` | string | `high` | Exit with code 1 if findings at this severity or above are found |

Example:

```bash
# Run all stages, output HTML, fail CI on high+ findings
sentinel scan \
  --repo https://github.com/your-org/your-repo \
  --domain your-app.com \
  --format html \
  --fail-on high
```

---

### `sentinel dashboard`

Launches the local web dashboard to browse and triage findings from the most recent scan (or a specified report file).

```bash
sentinel dashboard [flags]
```

| Flag | Type | Default | Description |
|---|---|---|---|
| `--report` | string | `./sentinel-report` | Path to the findings directory or JSON file to load |
| `--port` | int | `4000` | Port to serve the dashboard on |
| `--open` | bool | `true` | Automatically open the dashboard in a browser |

Example:

```bash
sentinel dashboard --report ./sentinel-report --port 4000
```

---

### `sentinel report`

Converts an existing findings JSON file into a different output format without re-running a scan.

```bash
sentinel report [flags]
```

| Flag | Type | Default | Description |
|---|---|---|---|
| `--input` | string | `./sentinel-report/findings.json` | Path to findings JSON |
| `--format` | string | `html` | Output format: `html`, `markdown`, `sarif` |
| `--output` | string | `./report.html` | Output file path |

Example:

```bash
sentinel report --format sarif --output sentinel.sarif
```

---

### `sentinel diff`

Scans only the changed files in a PR or commit range rather than the full repo. Designed for use in CI where a full scan would be too slow.

```bash
sentinel diff [flags]
```

| Flag | Type | Default | Description |
|---|---|---|---|
| `--base` | string | `main` | Base branch or commit SHA to diff against |
| `--head` | string | `HEAD` | Head branch or commit SHA |
| `--repo` | string | — | GitHub repo URL (required) |
| `--fail-on` | string | `high` | Exit with code 1 if findings at this severity or above are found |

Example:

```bash
sentinel diff --base main --head feature/new-api-routes --repo https://github.com/your-org/your-repo
```

---

## Dashboard

Running `sentinel dashboard` starts a lightweight local web server (default port 4000) that serves a browser UI for exploring scan findings. It reads from the most recent `findings.json` in the output directory, or from a path you specify with `--report`.

The dashboard shows all findings unified across the three scan stages. You can filter by stage, severity (critical / high / medium / low / info), and finding type. Each finding shows the affected file or endpoint, the CWE ID where applicable, and the raw evidence — the code snippet or DNS record that triggered it. You can mark findings as resolved, false positive, or accepted risk; these annotations are saved back to the findings JSON so they persist across sessions.

<!-- TODO: screenshot the dashboard findings view and save to ./assets/dashboard-findings.png -->
![Dashboard findings view](./assets/dashboard-findings.png)

*Findings view — filter by stage and severity, click any row to see the full evidence and remediation guidance.*

The intended workflow is: run `sentinel scan` in CI, download the findings artifact, then run `sentinel dashboard --report ./findings.json` locally to triage before filing GitHub issues.

---

## Quickstart

**1. Install**

```bash
pip install sentinel-sec
```

**2. Set your LLM API key**

```bash
export ANTHROPIC_API_KEY=sk-...
# Or for OpenAI:
# export OPENAI_API_KEY=sk-...
```

**3. Run a full scan**

```bash
sentinel scan --repo https://github.com/your-org/your-repo --domain your-app.com
```

**4. Open the dashboard**

```bash
sentinel dashboard
# Opens http://localhost:4000 automatically
```

**5. Export a report**

```bash
sentinel report --format html --output report.html
```

> **Tip:** To scan only changed files in a PR, use `sentinel diff` instead of `sentinel scan`. This is much faster in CI.

> **Tip:** To use as a GitHub Action, see the [workflow template](.github/workflows/sentinel.yml) in this repo.

---

## Configuration

Sentinel is configured via a `sentinel.yml` file at the repo root.

```yaml
# sentinel.yml

target:
  repo: https://github.com/your-org/your-repo  # GitHub repo to scan
  domain: your-app.com                          # Domain for attack surface scan

stages:
  attack_surface: true   # Toggle Subfinder + Shodan enumeration
  dependency_risk: true  # Toggle reachability-aware dep scoring
  auth_review: true      # Toggle LLM auth analysis

llm:
  provider: anthropic    # anthropic | openai
  model: claude-sonnet-4-20250514

output:
  format: json           # json | html | markdown
  path: ./sentinel-report

dashboard:
  port: 4000             # Port for `sentinel dashboard`
  auto_open: true        # Open browser automatically on launch

thresholds:
  dep_risk_score: 7.0    # Fail CI if any dep scores above this (0–10)
  auth_severity: high    # Fail CI at this severity or above
```

---

## Architecture

Sentinel takes a repo URL and a domain as inputs, runs three analysis stages in parallel where possible, and merges all results into a unified findings object that feeds both the CLI output and the web dashboard.

```
┌─────────────┐     ┌──────────────────────┐     ┌───────────────────┐     ┌─────────────────┐
│ GitHub Repo │────▶│ Stage 2: Dep Scorer  │────▶│                   │     │   CLI Output    │
└─────────────┘     └──────────────────────┘     │  Unified Findings │────▶│  (stdout/file)  │
                                                  │   (JSON schema)   │     └─────────────────┘
┌─────────────┐     ┌──────────────────────┐     │                   │
│   Domain    │────▶│ Stage 1: Atk Surface │────▶│                   │     ┌─────────────────┐
└─────────────┘     └──────────────────────┘     │                   │────▶│  Web Dashboard  │
                                                  │                   │     │  (port 4000)    │
┌─────────────┐     ┌──────────────────────┐     │                   │     └─────────────────┘
│   PR Diff   │────▶│ Stage 3: Auth Review │────▶│                   │
└─────────────┘     └──────────────────────┘     └───────────────────┘
```

---

## Threat Model

Sentinel is designed to detect three categories of risk: exposed infrastructure (subdomains, open ports, dangling DNS, misconfigured TLS), vulnerable and reachable dependencies (packages with known CVEs where the vulnerable code path is actually called), and authorization logic flaws introduced at the code level (routes missing auth middleware, IDOR patterns, privilege escalation paths).

Sentinel is explicitly not a penetration testing tool, a WAF, or a runtime monitor. It operates at development time — before code ships — not in production. It does not exploit findings, send traffic to production systems, or perform active port scanning. All attack surface enumeration uses passive sources (Subfinder's certificate transparency and DNS data, Shodan's indexed results).

Sentinel reads repo contents and makes DNS and Shodan API queries. The auth review stage sends code snippets — specifically the diff and auth middleware context — to an external LLM API (Anthropic or OpenAI, per your config). Users should review the data-handling implications of this before scanning private repos. The LLM is never sent full repo contents, only the relevant diff and targeted context windows.

LLM-based auth review can produce false positives, particularly in codebases with non-standard middleware patterns. Findings should always be triaged by a human (using the dashboard or otherwise) before being treated as confirmed vulnerabilities. The reachability analysis is conservative by design — if in doubt, Sentinel will flag rather than suppress.

---

## Roadmap

- [ ] SARIF output format for native GitHub Security tab integration
- [ ] Support for JavaScript/TypeScript repos (currently Python only)
- [ ] Semgrep rule generation from LLM auth findings
- [ ] GitLab CI template
- [ ] Historical trend tracking and scan diff view in dashboard
- [ ] Local LLM support (Ollama)
- [ ] Dashboard: team mode with shared annotations (requires a backend)

---

## Contributing

Contributions are welcome. The best way to start is to open an issue describing the bug or feature you have in mind before submitting a PR — this ensures the work aligns with the project direction and avoids duplicated effort.

See [CONTRIBUTING.md](./CONTRIBUTING.md) for detailed guidelines on setting up a dev environment, running tests, and the PR review process.

### Running tests locally

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

---

## License

Sentinel is released under the [MIT License](./LICENSE).
