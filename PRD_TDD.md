# Sentinel — Defender Attack Surface, Exploitability-Aware Dependencies & Semantic LLM Code Security
## Product Requirements & Technical Design Document

**Version:** 0.3  
**Date:** 2026-04-15  
**Author:** Angad Josan  
**Status:** Draft

---

## Table of Contents

1. [Problem Statement](#1-problem-statement)
2. [Product Goals & Non-Goals](#2-product-goals--non-goals)
3. [User Personas & Flows](#3-user-personas--flows)
4. [System Architecture Overview](#4-system-architecture-overview)
5. [GitHub Integration Design](#5-github-integration-design)
6. [Agent Orchestration & Trigger Model](#6-agent-orchestration--trigger-model)
7. [Module 1 — Attack Surface Mapping](#7-module-1--attack-surface-mapping)
8. [Module 2 — Dependency Risk Scoring](#8-module-2--dependency-risk-scoring)
9. [Module 3 — Semantic LLM Code Security Review (PR / Diff)](#9-module-3--semantic-llm-code-security-review-pr--diff)
10. [CVE Data Strategy: Caching vs. Live Query](#10-cve-data-strategy-caching-vs-live-query)
11. [Reachability Analysis Engine](#11-reachability-analysis-engine)
12. [Data Models](#12-data-models)
13. [API Design](#13-api-design)
14. [LLM Integration Layer](#14-llm-integration-layer)
15. [Dashboard & CLI](#15-dashboard--cli)
16. [Security Architecture](#16-security-architecture)
17. [Demo Strategy](#17-demo-strategy)
18. [Infrastructure & Deployment](#18-infrastructure--deployment)
19. [Future Work](#19-future-work)
20. [Implementation Phases & Milestone Plan](#20-implementation-phases--milestone-plan)
21. [Testing Strategy](#21-testing-strategy)
22. [Agent Context & Memory Architecture](#22-agent-context--memory-architecture)
23. [Module Interfaces & Internal API Contracts](#23-module-interfaces--internal-api-contracts)
24. [Configuration Architecture](#24-configuration-architecture)
25. [Dashboard Technical Spec](#25-dashboard-technical-spec)
26. [LLM Prompt Engineering Reference](#26-llm-prompt-engineering-reference)
27. [CLI Implementation Reference](#27-cli-implementation-reference)
28. [Observability & Performance Targets](#28-observability--performance-targets)
29. [Local Development Setup](#29-local-development-setup)
30. [Migration Guide: auth_findings → code_security_findings](#30-migration-guide-auth_findings--code_security_findings)
31. [Signal/Noise Reduction: Production Heuristics](#31-signalnoise-reduction-production-heuristics)

---

## 1. Problem Statement

Modern engineering teams have overlapping blind spots that usually live in separate tools (or no tool at all):

1. **What attack surface does this repo actually expose on the internet?** Subdomains, endpoints, TLS configs, dangling DNS — nobody has a live, repo-linked picture of this.
2. **Which vulnerable dependencies are actually reachable?** Scanners like Dependabot flag thousands of CVEs, most unreachable. Teams tune them out. The signal-to-noise is terrible.
3. **What risky *semantics* shipped in this PR?** Broken access control and IDOR are the headline failures, but the same gap exists for injection sinks, secrets in diffs, SSRF-shaped fetches, unsafe deserialization, and weak crypto defaults — patterns that regex-heavy SAST often misses without context.

These questions share a root: *what can an attacker actually reach and exploit?* Sentinel answers them from a single GitHub integration (or local CLI), unified into one risk surface per repo: **defender attack-surface inventory**, **exploitability-weighted dependencies (npm + PyPI in v1)**, and **LLM-backed semantic review** of the change.

---

## 2. Product Goals & Non-Goals

### Goals

- **G1.** One-click GitHub App install — zero config to get value on an existing repo.
- **G2.** **Defender-facing** attack-surface enumeration (Crossfeed-inspired inventory: subdomains, TLS, DNS, indexed exposure) tied to a specific repo/org, updated on push to main and on schedule.
- **G3.** Dependency risk scoring that weights CVEs by reachability, not just existence.
- **G4.** AI-powered PR / diff review that flags **semantic** security issues before merge: access control and auth middleware alignment, IDOR-shaped handlers, common injection flows, secrets in code, SSRF-shaped network calls, dangerous deserialization, and weak TLS/crypto usage — with structured JSON findings, CWE mapping where applicable, and bounded context (never full-repo dump to the LLM).
- **G5.** Web dashboard and CLI that surface findings in a digestible, shareable format.
- **G6.** High demo value — findings should be dramatic and explainable in a tweet.
- **G7.** **CLI-native scan UX:** `sentinel scan` is the primary command. By default it (a) streams **Rich** terminal output (progress, per-stage summaries, and **code-security** findings with short LLM rationale), (b) persists unified artifacts to disk, and (c) **starts the local dashboard** bound to that report (same behavior as `sentinel dashboard`), respecting `dashboard.auto_open`. **`--quiet`** disables (a) and (c) for CI and headless agents — artifacts and exit codes only.
- **G8.** **LLM-native output:** CLI text is written so humans *and* coding agents can triage from logs — especially the **code security** stage, which includes location, category, severity, and a concise natural-language explanation alongside structured IDs (CWE, file:line). Quiet mode still writes full JSON for machines.
- **G9.** **CLI without GitHub App:** Local `sentinel scan --repo <url>` works on any repository the operator can read — typically a **public** GitHub URL via anonymous clone or API, or a **private** repo when `GITHUB_TOKEN` / `gh auth` supplies credentials. No App install is required for this path.

### Non-Goals (v1)

- **NG1.** Automated exploitation or active fuzzing (passive enumeration only).
- **NG2.** Non-GitHub SCM support (GitLab, Bitbucket) — out of scope for v1.
- **NG3.** **Formal verification** or **binary-only** closed-source dependency blobs without lockfile/manifest signals — out of scope for v1.
- **NG4.** **Guaranteed completeness** — the LLM stage is a high-signal reviewer, not a soundness proof; deterministic dep and surface stages complement it but cannot eliminate all logical bugs.
- **NG5.** **Hosted** Sentinel (GitHub App / multi-tenant cloud) scanning a repo **without** that customer having installed the App — avoids drive-by abuse, ensures we only read code under explicit OAuth/App grants, and keeps private repos out of our infra unless authorized. **This does not apply to the local CLI:** running Sentinel on your laptop against a public repo you clone is in scope (G9).

### Scope split: hosted vs CLI

| Surface | Who needs GitHub App install? | Public repo URL |
|---------|------------------------------|-----------------|
| **Hosted SaaS / GitHub App webhooks** | Yes, per org/repo install | Only after install (or v2 hosted scanner) |
| **Local `sentinel` CLI** | No | Yes — clone or fetch what your token can read |

---

## 3. User Personas & Flows

### Personas

| Persona | Description | Primary Use |
|---------|-------------|-------------|
| **Solo Dev / Indie Hacker** | Building a SaaS, no dedicated security team | Install, forget, get alerts when something is wrong |
| **Security Engineer** | On a 10-100 person eng team | Triage dashboard, integrate into existing workflows |
| **Engineering Manager** | Wants visibility without false alarms | Weekly digest, risk score per repo |
| **Ashwin (Evaluator)** | Technically sophisticated, wants to see real findings | Demo mode, dramatic first-run output |

---

### User Flow 1 — First Install (GitHub App)

```
User lands on sentinel.dev
  → clicks "Add to GitHub"
  → GitHub OAuth: select org or repo
  → GitHub App installed with webhooks + read permissions
  → Sentinel kicks off full baseline scan:
      1. Attack surface enumeration (background, ~2-5 min)
      2. Dependency graph analysis (background, ~30s-2min)
      3. No code review yet (triggered per-PR)
  → User receives email/Slack: "Sentinel found X findings on first scan"
  → User visits dashboard, sees:
      - Attack surface: N subdomains, M exposed ports, K TLS issues
      - Dep risk: top 5 vulnerable + reachable packages, scored
      - Code: "Ready — reviewing next PR"
```

---

### User Flow 2 — PR Opened (semantic security review)

```
Dev opens PR: "feat: add /api/admin/users endpoint"
  → GitHub sends pull_request webhook (action: opened/synchronize)
  → Sentinel receives webhook
  → Diff extraction: identify new/modified files
  → Route / handler detection: find new endpoints and high-risk sinks in diff
  → Context fetch: auth middleware patterns, existing protected routes, config that defines trust boundaries
  → LLM prompt: structured review for access control, IDOR, injection, secrets, SSRF-shaped calls, deserialization, crypto/TLS misuse
  → Model returns JSON: [{ location, category, issue_type, severity, cwe_id, explanation, fix_suggestion }]
  → Sentinel posts GitHub Check Run (status: action_required) + PR comment
  → Developer sees inline annotation: e.g. "⚠ New admin route may bypass established auth middleware" or "⚠ User input flows to shell/exec sink"
  → Dev fixes it, pushes
  → Sentinel re-reviews, posts: "✓ Code security review: no issues found"
```

---

### User Flow 3 — Dependency File Changed

```
Dev pushes: updated requirements.txt (adds `requests==2.26.0`)
  → GitHub push webhook
  → Sentinel detects dep file change (requirements.txt, package.json, etc.)
  → Runs dependency diff: new packages + version changes
  → Queries CVE cache (OSV.dev data, refreshed daily):
      - requests 2.26.0 → CVE-2023-32681 (CVSS 6.1)
  → Reachability check: does any code path import `requests.Session.resolve_redirects`?
  → If reachable: severity escalated, GitHub comment posted
  → If unreachable: logged to dashboard, low-priority annotation
  → Dashboard shows: "1 new vulnerable dependency added — reachable"
```

---

### User Flow 4 — Dashboard Browse

```
User opens dashboard
  → Sees repo list with per-repo risk score (0-100)
  → Clicks into a repo:
      → "Attack Surface" tab:
          - Subdomain map (live/dead, cert info)
          - Open ports table
          - Dangling DNS records
          - Last scanned timestamp + rescan button
      → "Dependencies" tab:
          - Risk-scored package list, sortable
          - CVE details + reachability trace ("called via app.py:134 → utils/http.py:22")
          - Fix recommendations
      → "Code security" tab:
          - PR history with review results
          - Open issues (unfixed findings by category)
          - Detected middleware / trust-boundary map (auth patterns, gateway headers, etc.)
```

---

### User Flow 5 — CLI (Power User / CI)

```bash
$ sentinel scan --repo org/repo
$ sentinel scan --repo org/repo --module deps
$ sentinel pr --repo org/repo --pr 142
$ sentinel surface --domain myapp.com
$ sentinel report --repo org/repo --format json > report.json
```

---

### User Flow 6 — `sentinel scan` (CLI-native default + quiet mode)

**Default (interactive / agent-in-terminal):**

```
$ sentinel scan --repo org/repo [--domain myapp.com]

  → Stdout: Rich UI — per-stage progress, summary tables, top N findings per stage
  → Code security stage: each row includes location, category, severity, CWE, and a 1–2 line LLM rationale
       (optimized for human skim and for agents reading build logs)
  → Disk: unified findings + configured export formats under --output (default ./sentinel-report)
  → Local dashboard: binds dashboard.port (default 4000), serves the report just written;
       opens browser when dashboard.auto_open is true (sentinel.yml)
  → User triages in terminal, browser, or both without running a second command first
```

**Quiet (CI, log-shy pipelines, “write files only”):**

```
$ sentinel scan --repo org/repo --quiet

  → No Rich tables, no progress UI on stdout (errors → stderr only)
  → Does not start the local dashboard process
  → Artifacts and --fail-on exit codes unchanged
```

**Optional:** `--no-dashboard` — keep full Rich CLI output but skip auto-starting the dashboard (terminal-only review).

---

## 4. System Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        GitHub                                   │
│  Webhooks (push, PR, installation) ──► Sentinel GitHub App      │
└─────────────────────────────────────┬───────────────────────────┘
                                      │ HTTPS POST
                                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Sentinel API (FastAPI)                      │
│  /webhooks/github   /api/v1/*   /dashboard                      │
│                                                                 │
│  Webhook Router ──► Event Classifier ──► Task Queue (Celery)    │
└────────────────────────┬────────────────────────────────────────┘
                         │ enqueue jobs
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Worker Pool (Celery)                        │
│                                                                 │
│  ┌──────────────────┐  ┌─────────────────┐  ┌───────────────┐  │
  │  │  Attack Surface  │  │  Dep Risk Score │  │ LLM Security  │  │
  │  │  Worker          │  │  Worker         │  │  Worker       │  │
  │  │                  │  │                 │  │               │  │
  │  │  subfinder       │  │  dep parser     │  │  diff parser  │  │
  │  │  httpx           │  │  OSV.dev cache  │  │  route/sink   │  │
  │  │  shodan API      │  │  reachability   │  │  detect + LLM │  │
  │  │  DNS resolver    │  │  engine         │  │               │  │
│  └────────┬─────────┘  └────────┬────────┘  └───────┬───────┘  │
└───────────┼─────────────────────┼───────────────────┼──────────┘
            │                     │                   │
            ▼                     ▼                   ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Data Layer                                 │
│                                                                 │
│  PostgreSQL (findings, repos, scans)                            │
│  Redis (task queue, CVE cache, rate limit state)                │
│  S3 / local FS (raw scan artifacts, LLM prompt logs)            │
└─────────────────────────────────────────────────────────────────┘
            │
            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Reporting Layer                              │
│  GitHub Check Runs  │  PR Comments  │  Dashboard  │  CLI        │
└─────────────────────────────────────────────────────────────────┘
```

**Stack:**
| Layer | Technology |
|-------|-----------|
| API | Python 3.12, FastAPI |
| Task Queue | Celery 5.x + Redis 8 |
| Database | PostgreSQL 18 |
| Cache | Redis 8 |
| Attack Surface | subfinder, httpx, Shodan API, dnspython |
| Dep Analysis | custom parser + OSV.dev REST API |
| Reachability | tree-sitter (Python/JS AST) |
| AI Review | Anthropic Claude API (claude-sonnet-4-6) |
| Dashboard | Next.js 16 (App Router) |
| CLI | Python, Click + Rich |
| Deployment | Railway (API + workers), Vercel (dashboard), Supabase (DB), Upstash (Redis) |

---

## 5. GitHub Integration Design

### GitHub App (not GitHub Actions)

Sentinel is a **GitHub App**, not a GitHub Action. This distinction matters:

| | GitHub App | GitHub Action |
|---|---|---|
| Install UX | One-click on repo or org | Must add YAML to each repo |
| Permissions | Fine-grained via App manifest | Workflow-scoped |
| Webhooks | Centralized, managed by us | Per-repo `.github/workflows/` |
| Check Runs | Full access | Available but noisy |
| Rate limits | App-level (5000 req/hr/install) | Action-runner level |
| Demo value | "Install and done" | Requires repo commit |

**GitHub App Permissions Required:**

```yaml
# App manifest permissions
repository_permissions:
  contents: read          # read code, dep files
  pull_requests: write    # post PR comments
  checks: write           # post Check Runs
  statuses: write         # set commit status
  metadata: read          # repo info

organization_permissions:
  members: read           # enumerate repos in org

events:
  - push
  - pull_request
  - installation
  - installation_repositories
```

### Webhook Handler

```python
# POST /webhooks/github
# Validates X-Hub-Signature-256 before any processing

def route_webhook(event_type: str, payload: dict) -> None:
    match event_type:
        case "installation":
            enqueue_baseline_scan(payload["installation"])
        case "push" if targets_default_branch(payload):
            enqueue_attack_surface_scan(payload)
            if dep_files_changed(payload):
                enqueue_dep_scan(payload)
        case "push" if dep_files_changed(payload):
            enqueue_dep_scan(payload)
        case "pull_request" if payload["action"] in ("opened", "synchronize"):
            enqueue_pr_review(payload)
```

**Dep file detection** — any change to:
`requirements.txt`, `requirements*.txt`, `Pipfile`, `Pipfile.lock`, `pyproject.toml`, `setup.py`, `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Cargo.toml`, `go.mod`, `go.sum`

---

## 6. Agent Orchestration & Trigger Model

### Trigger Matrix

| Event | Attack Surface | Dep Risk | LLM Code Security |
|-------|---------------|----------|----------------|
| App installed | ✓ (full scan) | ✓ (full scan) | — |
| Push to main | ✓ (incremental) | Only if dep files changed | — |
| Push to any branch | — | Only if dep files changed | — |
| PR opened/updated | — | ✓ (diff only) | ✓ |
| PR merged | — | — | — |
| Scheduled (daily 3am) | ✓ (full rescan) | ✓ (refresh CVE cache) | — |
| Manual (CLI/dashboard) | ✓ | ✓ | ✓ |

### Rationale

- **Attack surface** changes slowly (infra changes). Full rescan daily + incremental on push is sufficient. Heavy tool, don't over-trigger.
- **Dep risk** is cheap and must fire on dep file changes. Also runs on PR to catch "you're adding a bad package."
- **LLM code security** fires on every PR push — this is the most latency-sensitive, must complete before PR review window.

### Task Queue Design

```
Queues (Celery):
  - high_priority:   PR reviews (target: < 60s end-to-end)
  - default:         Dep scans
  - low_priority:    Attack surface scans (can take 2-5 min)
  - scheduled:       Daily refresh jobs

Task deduplication:
  - attack_surface:{repo_id}:{branch} — dedupe by repo+branch, 1hr lock
  - dep_scan:{repo_id}:{commit_sha} — dedupe by exact commit
  - pr_review:{repo_id}:{pr_number}:{head_sha} — dedupe by head SHA
```

### Task State Machine

```
PENDING → RUNNING → COMPLETE
                  → FAILED → RETRIED (max 3x, exponential backoff)
                  → TIMEOUT
```

---

## 7. Module 1 — Attack Surface Mapping

### Goal
Given a GitHub repo (and optional domain seeds), build a **defender-facing inventory** of internet-facing assets and misconfigurations tied to that software — **Crossfeed-inspired** in purpose (continuous visibility for operators securing critical-facing web estates), **lightweight** in deployment: passive discovery, DNS hygiene, TLS analysis, and indexed third-party intel — **not** an offensive reconnaissance or exploitation toolkit.

### Defender framing (Crossfeed-inspired)

- **Who it is for:** security engineers, SREs, and program owners who need to answer “what do we expose, and is it configured safely?” — analogous to federal/state **critical infrastructure and elections-adjacent** surface monitoring, scaled to a repo-or-domain scope.
- **What it avoids:** coordinated offensive scanning, credential stuffing, or exploit payloads. No “weaponized” positioning in docs or UX.
- **Inputs:** registrable domains inferred from the repo **or** supplied via `--domain`; optional org-owned seed lists in config for hosted product.
- **Outputs:** unified findings suitable for **triage and remediation** (TLS upgrade, dangling DNS removal, port exposure review), exportable to SARIF/HTML for existing workflows.

### CLI: `--domain` flag (optional seed)

Passive enumeration (Subfinder, Shodan, etc.) needs one or more **seed registrable domains**. The `--domain` argument is **optional**:

- **If provided:** use it as the **primary** seed (merged with repo-derived seeds from Step 1 — dedupe). Best when you know production hostname (e.g. `app.example.com`’s registrable domain `example.com`).
- **If omitted:** run **Step 1 only** (`parse_repo_for_domains`) to collect candidates from metadata, config, `homepage`, README URLs, etc. Enumerate each candidate; if the set is **empty**, the attack-surface stage completes with **no hosts** and the CLI prints a hint to pass `--domain` for full surface coverage.

Dependency and **code security** stages do **not** require `--domain`; they operate on cloned source only.

### Input Sources

1. **Repo metadata**: `github.com/org/repo` → owner domain heuristics
2. **Code scan**: grep for hardcoded domains, env var references to `DOMAIN`, `HOST`, `BASE_URL`
3. **Config files**: `.env.example`, `docker-compose.yml`, `k8s/`, `terraform/`, `*.tf`, `Caddyfile`, `nginx.conf`
4. **README + docs**: regex for `https://` links
5. **GitHub Pages**: check if `org.github.io` is live
6. **Package.json `homepage` field** (common in React apps)

### Enumeration Pipeline

```
Step 1: Domain Collection
  ├── parse_repo_for_domains(repo) → Set[str]
  └── deduplicate + normalize

Step 2: Subdomain Enumeration
  ├── subfinder -d {domain} -silent -all
  │     sources: crt.sh, hackertarget, alienvault, dnsdumpster, etc.
  └── amass enum -passive -d {domain} (if available)

Step 3: HTTP Probing
  └── httpx -l subdomains.txt -status-code -title -tech-detect -tls-grab
        outputs: live hosts, status codes, tech stack, cert info

Step 4: Port Scanning (Shodan, not active scan)
  └── shodan host {ip} → open ports, banners, vulns
      (passive — use Shodan's indexed data, no active probing)

Step 5: DNS Analysis
  ├── Check for dangling CNAME (points to deprovisioned cloud resource)
  │     known dangling targets: *.s3.amazonaws.com, *.azurewebsites.net,
  │     *.cloudapp.net, *.herokuapp.com, *.github.io, *.netlify.app
  └── Check MX/SPF/DMARC records for email security posture

Step 6: TLS Analysis
  └── Parse httpx tls-grab output:
        - cert expiry
        - cipher suites (flag TLS 1.0/1.1)
        - cert SANs (reveals more subdomains)
        - mismatched hostnames

Step 7: HTTP security posture (in-scope hosts only)
  └── From httpx / bounded GET probes against hosts already tied to the seed:
        - HSTS presence and basic redirect-to-HTTPS behavior
        - Content-Security-Policy / X-Frame-Options / Referrer-Policy signals (informational vs strict)
        - Cookie `Secure` / `HttpOnly` hints where response headers expose Set-Cookie
  (Recommendations only — no exploitation or session abuse.)
```

### Output Schema

```python
@dataclass
class AttackSurfaceFinding:
    repo_id: str
    scan_id: str
    host: str                          # "api.myapp.com"
    ip: Optional[str]
    status: str                        # "live" | "dead" | "dangling"
    ports: List[int]                   # [80, 443, 8080]
    tls: Optional[TLSInfo]
    technologies: List[str]            # ["nginx", "React", "Cloudflare"]
    issues: List[SurfaceIssue]         # dangling DNS, expired cert, etc.
    discovered_via: str                # "subfinder" | "repo_scan" | "cert_san"
    first_seen: datetime
    last_seen: datetime

@dataclass  
class SurfaceIssue:
    type: str    # "dangling_cname" | "expired_cert" | "tls_weak_cipher" | "open_port"
    severity: str  # "critical" | "high" | "medium" | "low" | "info"
    detail: str
    cve: Optional[str]  # if Shodan reports a CVE on the service
```

### Dangling DNS Detection Logic

```python
DANGLING_PATTERNS = {
    r"\.s3\.amazonaws\.com$": check_s3_bucket_exists,
    r"\.azurewebsites\.net$": check_azure_site_exists,
    r"\.herokuapp\.com$": check_heroku_app_exists,
    r"\.netlify\.app$": check_netlify_site_exists,
    r"\.github\.io$": check_github_pages_exists,
    r"\.vercel\.app$": check_vercel_site_exists,
}

def is_dangling(cname_target: str) -> bool:
    for pattern, check_fn in DANGLING_PATTERNS.items():
        if re.search(pattern, cname_target):
            return not check_fn(cname_target)
    return False
```

---

## 8. Module 2 — Dependency Risk Scoring

### Goal
Score each dependency by **practical exploitability** in *this* codebase — not CVE count alone: **reachable vulnerable symbols** (where OSV provides them), **transitive exposure**, **patch cadence**, **known exploits**, and **depth in the graph**. **PyPI** and **npm** are **v1 co-primary** ecosystems (equal product priority); others follow per parser maturity.

### Dependency Parsers

**v1 co-primary ecosystems — npm and PyPI** (equal footing in scoring, cache keys, and dashboard UX):

| Ecosystem | Files | Parser |
|-----------|-------|--------|
| **PyPI** | `requirements.txt`, `Pipfile.lock`, `pyproject.toml`, `poetry.lock` | custom regex + `tomllib` / lockfile parsers |
| **npm** | `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` | JSON + lockfile-native graph extraction |

Extended matrix (v2+):

| Ecosystem | Files | Notes |
|-----------|-------|--------|
| Go | `go.mod`, `go.sum` | module graph + proxy metadata |
| Rust | `Cargo.lock` | crates.io via OSV |
| JVM / .NET / Ruby | Maven, Gradle, `*.csproj`, `Gemfile.lock` | OSV ecosystem mapping |

### CVE Data Pipeline

**Data source:** OSV.dev (Open Source Vulnerabilities)
- REST API: `https://api.osv.dev/v1/query`
- Also bulk download: `https://osv-vulnerabilities.storage.googleapis.com/`
- Covers: PyPI, npm, crates.io, Go, Maven, RubyGems, NuGet, etc.
- Updated multiple times per day

**Supplementary:** NVD (NIST) for CVSS scores when OSV data is thin.

**Why OSV over Snyk/GitHub Advisory DB:**
- Free, no rate limits on bulk
- Machine-readable, normalized format
- Covers transitive vulnerabilities explicitly
- Can be fully self-hosted if needed

### CVE Caching Strategy

```
┌────────────────────────────────────────────────────────┐
│  Redis CVE Cache                                       │
│                                                        │
│  Key: osv:{ecosystem}:{package}:{version}              │
│  Value: serialized List[Vulnerability]                 │
│  TTL: 24 hours                                         │
│                                                        │
│  Key: osv:bulk_sync_ts                                 │
│  Value: last bulk sync timestamp                       │
│  TTL: none (manually managed)                          │
└────────────────────────────────────────────────────────┘

Cache miss → query OSV.dev API → cache result → return
Cache hit → return immediately

Nightly job (3am UTC):
  → download OSV bulk data for PyPI + npm
  → diff against cached data
  → invalidate changed entries
  → log newly discovered CVEs affecting tracked repos
  → if critical CVE (CVSS >= 9.0) hits a tracked package:
      → immediately enqueue dep_scan for all affected repos
      → notify via email/Slack
```

**Decision rationale:** Cache CVE data (not live query on every scan) because:
1. OSV bulk data is updated ~hourly; daily refresh is sufficient for most use cases
2. Live queries add 200-500ms per package; a typical repo has 50-200 deps → unacceptable latency
3. Allows offline operation and avoids rate limit surprises
4. Exception: critical CVEs (CVSS >= 9.0) trigger immediate live re-query

### Dependency Risk Score Algorithm

```python
def score_dependency(pkg: Package, vulns: List[Vulnerability], reachability: ReachabilityResult) -> float:
    """
    Returns a risk score from 0.0 to 10.0
    """
    if not vulns:
        return 0.0
    
    max_cvss = max(v.cvss_score for v in vulns)
    
    # Reachability multiplier: 1.0 if reachable, 0.2 if not
    reach_mult = 1.0 if reachability.is_reachable else 0.2
    
    # Patch cadence: penalize packages with slow/no patches
    patch_penalty = compute_patch_penalty(pkg)  # 0.0 - 1.0
    
    # Transitive depth: direct dep > transitive (slight bonus for directness)
    depth_mult = 1.0 if reachability.depth == 0 else max(0.7, 1.0 - 0.05 * reachability.depth)
    
    # Exploit availability: known public exploits boost score
    exploit_mult = 1.3 if any(v.has_known_exploit for v in vulns) else 1.0
    
    score = max_cvss * reach_mult * depth_mult * exploit_mult + patch_penalty
    return min(score, 10.0)
```

**Patch cadence scoring:** `patch_penalty` checks PyPI/npm release history. If the last release of a vulnerable package is > 12 months old and no fix exists: +1.5 penalty. This captures "abandoned package with CVE" which is effectively unfix-able.

### Output Schema

```python
@dataclass
class DepRiskFinding:
    package_name: str
    version: str
    ecosystem: str
    risk_score: float            # 0.0 - 10.0
    cvss_max: float
    vulns: List[CVERef]
    is_reachable: bool
    reachability_trace: Optional[str]  # "app.py:134 → utils/http.py:22 → requests.Session"
    is_direct: bool
    transitive_chain: List[str]  # ["myapp", "boto3", "urllib3"]
    fix_version: Optional[str]
    fix_available: bool
    patch_lag_days: Optional[int]
```

---

## 9. Module 3 — Semantic LLM Code Security Review (PR / Diff)

### Goal
On every PR (or `sentinel diff` in CI), perform **open-source, semantic security review** of the change: not regex-only SAST, but LLM reasoning over **bounded** context — the same product class as “does this route bypass auth middleware?” extended to **OWASP-style** categories that need **meaning** (data flow, trust boundaries, framework conventions).

**In scope (v1 — all first-class in prompts and schema):**

| Category | Examples |
|----------|----------|
| **Access control** | Missing auth middleware, broken middleware chain, IDOR-shaped handlers, horizontal/vertical privilege issues, auth bypass via alternate paths |
| **Injection** | SQL/command/template injection when user input reaches a sink (heuristic + semantic) |
| **Secrets & credentials** | API keys, tokens, private keys, passwords introduced or logged in the diff |
| **SSRF / unsafe fetch** | User-controlled URL/host reaching HTTP client, file, or redirect chains |
| **Deserialization** | Unsafe pickle/YAML/`eval`-class patterns on untrusted data |
| **Crypto / TLS** | Weak algorithms, `InsecureSkipVerify`, hardcoded IVs, misuse of JWT verify flags |

**Configurable:** `sentinel.yml` → `llm.code_security.categories` may **subset** the above for noisy repos; default is **all** categories enabled.

**Explicit non-goals for this module:** formal verification, guaranteed soundness, or reviewing code not present in the diff/context window.

### Static pre-analysis (feeds the LLM)

**Step 1: Detect framework** — same `FRAMEWORK_SIGNATURES` heuristic as before (FastAPI, Flask, Express, Django, Next.js API routes, Gin, etc.).

**Step 2: Extract structural signals from the diff** — tree-sitter (or equivalent) over **changed files** only:

- New/changed **routes** and HTTP methods
- New **imports** of high-risk libraries (ORM raw SQL, child_process, `yaml.load`, `pickle`, outbound `fetch`/`axios`)
- **Sinks** and **sources** candidates (user input parameters, headers, body parsers)

**Step 3: Gather trust-boundary context** (not only “auth”):

- Middleware / guard patterns (`Depends`, `before_request`, Express middleware chain, Next.js middleware)
- Centralized error handlers and how they leak stack traces
- Existing examples of **correctly** protected routes and **safe** patterns in-repo (few-shot)

**Step 4: Build bounded prompt packs**

- Hard cap: `MAX_TOKENS_PER_PR_REVIEW` (see §14) — chunk by file if diff exceeds budget; prioritize route files and new handlers.
- Include: structured route list, middleware excerpt, diff hunks, optional `secrets_scan` pre-pass hits (deterministic high-entropy / known-pattern scan **on the diff only** to reduce LLM miss rate).

**Step 5: LLM system instruction (normative shape)**

The model must return **only** a JSON array of objects with at least:

- `category`: `access_control` | `injection` | `secrets` | `ssrf` | `deserialization` | `crypto_tls` | `other`
- `issue_type`: short machine slug (e.g. `missing_auth`, `idor`, `sql_injection`, `secret_in_diff`, `insecure_deserialization`)
- `route` (optional): HTTP route pattern if applicable, else `null`
- `method` (optional): HTTP method if applicable
- `file`, `line`: primary location
- `severity`: `critical` | `high` | `medium` | `low`
- `cwe_id` (optional): integer when the model can map confidently
- `explanation`, `fix_suggestion`: concise, actionable

If no issues: `[]`. Instruction: **do not flag** patterns that clearly match established safe usage in the provided middleware examples.

**Step 6: Post results to GitHub** (hosted) / write to unified findings (CLI)

```python
def post_pr_review(pr: PullRequest, findings: List[CodeSecurityFinding]) -> None:
    if not findings:
        create_check_run(pr, conclusion="success", title="Sentinel: Code security review — no issues")
        return
    create_check_run(
        pr,
        conclusion="action_required",
        title=f"Sentinel: {len(findings)} code security finding(s)",
        annotations=[finding_to_annotation(f) for f in findings],
    )
    post_pr_comment(pr, build_summary_comment(findings))
```

GitHub Check Run annotations remain the primary high-signal delivery path.

### Code security finding output schema

```python
@dataclass
class CodeSecurityFinding:
    category: Literal[
        "access_control", "injection", "secrets", "ssrf",
        "deserialization", "crypto_tls", "other",
    ]
    issue_type: str  # e.g. missing_auth, idor, sql_injection, secret_in_diff
    route: Optional[str]
    method: Optional[str]
    file: str
    line: Optional[int]
    severity: Literal["critical", "high", "medium", "low"]
    cwe_id: Optional[int]
    explanation: str
    fix_suggestion: str
    pr_number: int
    commit_sha: str
    reviewed_at: datetime
    llm_model: str
    prompt_tokens: int
    completion_tokens: int
```

**Storage note:** New deployments SHOULD use table `code_security_findings` (below). Existing installs MAY migrate from `auth_findings` via additive columns + backfill `category='access_control'`.

---

## 10. CVE Data Strategy: Caching vs. Live Query

### Decision: Tiered Cache with Nightly Bulk Sync

```
Tier 1 — Redis (hot cache, 24hr TTL):
  Per-package CVE lookups for actively-scanned repos.
  Populated on first scan, refreshed by nightly job.
  ~1-5ms lookup time.

Tier 2 — PostgreSQL (warm store):
  Full CVE records for all packages ever seen across all repos.
  Used for historical queries, trend analysis, search.
  Refreshed from OSV bulk download nightly.

Tier 3 — OSV.dev API (cold, live):
  Fallback for cache miss.
  Used for: new packages not yet cached, critical CVE re-check,
  forced refresh via dashboard.
```

### Nightly Sync Job (3am UTC)

```python
@celery_app.task
def nightly_cve_sync():
    ecosystems = ["PyPI", "npm"]  # v1
    for ecosystem in ecosystems:
        # Download compressed bulk data from OSV
        new_vulns = fetch_osv_bulk(ecosystem)
        # Diff against DB
        added, modified, removed = diff_vulns(new_vulns, db.get_all_vulns(ecosystem))
        # Update DB
        db.bulk_upsert_vulns(added + modified)
        # Invalidate Redis for modified packages
        for v in modified:
            redis.delete(f"osv:{ecosystem}:{v.package}:*")
        # Check if any tracked repo is newly affected by CRITICAL CVE
        check_critical_alerts(added, severity_threshold=9.0)
```

### Why Not Always-Live?

OSV.dev API has no official public rate limit documented, but:
- Bulk download is ~50MB compressed for PyPI — tractable nightly
- Per-query latency matters: a repo with 150 deps × 200ms/query = 30s scan time vs <1s with cache
- Bulk sync gives us the full dataset for free analytics (trending vulns, etc.)

---

## 11. Reachability Analysis Engine

This is the hardest part and the key differentiator.

### Approach: Conservative Call Graph + Import Tracing

Full interprocedural static analysis is too expensive for v1. Instead: **import reachability** — does the application code import the vulnerable module, and does it call a function in the affected module?

### Python Reachability

```python
def check_python_reachability(repo_path: str, package: str, vuln_functions: List[str]) -> ReachabilityResult:
    """
    Uses tree-sitter to build import graph and find calls to vulnerable functions.
    
    vuln_functions: from OSV "affected[].ecosystem_specific.imports" field
    """
    # Step 1: Find all files that import the package
    importing_files = []
    for py_file in glob(f"{repo_path}/**/*.py"):
        ast = parse_python(py_file)
        if imports_package(ast, package):
            importing_files.append(py_file)
    
    if not importing_files:
        return ReachabilityResult(is_reachable=False, reason="package not imported")
    
    # Step 2: Check if any vulnerable function is called
    for file in importing_files:
        ast = parse_python(file)
        for func in vuln_functions:
            calls = find_calls_to(ast, package, func)
            if calls:
                return ReachabilityResult(
                    is_reachable=True,
                    trace=f"{file}:{calls[0].line} → {package}.{func}",
                    depth=0  # direct
                )
    
    # Step 3: Mark as "imported but vulnerable function not called" — still non-zero risk
    return ReachabilityResult(
        is_reachable=False,
        reason="imported but vulnerable functions not directly called",
        partial=True  # show in UI as reduced risk, not zero
    )
```

**OSV `ecosystem_specific` field** often includes which specific functions are vulnerable (especially for PyPI). When this data is present, use it. When absent, fall back to "package imported = potentially reachable."

### JavaScript/TypeScript Reachability

Similar approach using `@babel/parser` or `acorn` for AST, checking `require()`/`import` statements and method calls.

### Transitive Reachability

For transitive deps (A → B → C, where C is vulnerable):
- v1: Flag as reachable at reduced risk score (0.6× multiplier vs direct)
- v2: Full transitive call graph

---

## 12. Data Models

### PostgreSQL Schema

```sql
-- Repositories tracked by Sentinel
CREATE TABLE repos (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    github_id BIGINT UNIQUE NOT NULL,
    owner TEXT NOT NULL,
    name TEXT NOT NULL,
    default_branch TEXT NOT NULL DEFAULT 'main',
    installation_id BIGINT NOT NULL,
    risk_score FLOAT DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    last_scanned_at TIMESTAMPTZ
);

-- Scans (one per trigger event)
CREATE TABLE scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repo_id UUID REFERENCES repos(id),
    scan_type TEXT NOT NULL,  -- 'attack_surface' | 'dep_risk' | 'code_security' | 'pr_review' (legacy alias)
    trigger TEXT NOT NULL,    -- 'push' | 'pr' | 'scheduled' | 'manual'
    commit_sha TEXT,
    pr_number INT,
    status TEXT NOT NULL DEFAULT 'pending',
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    error TEXT
);

-- Attack surface findings
CREATE TABLE surface_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id),
    repo_id UUID REFERENCES repos(id),
    host TEXT NOT NULL,
    ip TEXT,
    status TEXT NOT NULL,  -- 'live' | 'dead' | 'dangling'
    ports JSONB DEFAULT '[]',
    tls_info JSONB,
    technologies JSONB DEFAULT '[]',
    issues JSONB DEFAULT '[]',
    discovered_via TEXT,
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(repo_id, host)
);

-- Dependency findings
CREATE TABLE dep_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id),
    repo_id UUID REFERENCES repos(id),
    package_name TEXT NOT NULL,
    version TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    risk_score FLOAT NOT NULL,
    cvss_max FLOAT,
    vulns JSONB DEFAULT '[]',
    is_reachable BOOLEAN,
    reachability_trace TEXT,
    is_direct BOOLEAN,
    transitive_chain JSONB DEFAULT '[]',
    fix_version TEXT,
    fix_available BOOLEAN DEFAULT FALSE,
    patch_lag_days INT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Semantic LLM code security findings (supersedes legacy auth_findings)
CREATE TABLE code_security_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id),
    repo_id UUID REFERENCES repos(id),
    pr_number INT NOT NULL,
    commit_sha TEXT NOT NULL,
    category TEXT NOT NULL,  -- access_control | injection | secrets | ssrf | deserialization | crypto_tls | other
    issue_type TEXT NOT NULL,
    route TEXT,
    method TEXT,
    file TEXT NOT NULL,
    line INT,
    cwe_id INT,
    severity TEXT NOT NULL,
    explanation TEXT NOT NULL,
    fix_suggestion TEXT,
    resolved BOOLEAN DEFAULT FALSE,
    resolved_at TIMESTAMPTZ,
    llm_model TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
-- Legacy: CREATE TABLE auth_findings — migrate rows into code_security_findings with category='access_control'

-- CVE cache (warm store)
CREATE TABLE cve_cache (
    id TEXT PRIMARY KEY,  -- OSV vuln ID (e.g. "GHSA-...")
    ecosystem TEXT NOT NULL,
    package_name TEXT NOT NULL,
    affected_versions JSONB,
    cvss_score FLOAT,
    cvss_vector TEXT,
    has_known_exploit BOOLEAN DEFAULT FALSE,
    fix_versions JSONB,
    vuln_functions JSONB DEFAULT '[]',
    published_at TIMESTAMPTZ,
    modified_at TIMESTAMPTZ,
    cached_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX ON cve_cache(ecosystem, package_name);

-- GitHub installations
CREATE TABLE installations (
    id BIGINT PRIMARY KEY,  -- GitHub installation ID
    account_login TEXT NOT NULL,
    account_type TEXT NOT NULL,  -- 'User' | 'Organization'
    access_token TEXT,            -- encrypted
    token_expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

---

## 13. API Design

### REST API (`/api/v1/`)

```
Authentication: Bearer token (JWT, issued on GitHub OAuth callback)

GET  /api/v1/repos
     → List repos for authenticated user

GET  /api/v1/repos/{repo_id}
     → Repo details + current risk score

POST /api/v1/repos/{repo_id}/scan
     → Trigger manual scan
     body: { "modules": ["attack_surface", "deps", "code_security"] }

GET  /api/v1/repos/{repo_id}/surface
     → Attack surface findings (paginated)
     query: ?status=live&severity=high

GET  /api/v1/repos/{repo_id}/deps
     → Dependency findings (paginated)
     query: ?reachable=true&sort=risk_score

GET  /api/v1/repos/{repo_id}/code-security
     → LLM code security findings (all categories)
     query: ?resolved=false&pr=142&category=access_control
     (Legacy alias: GET .../auth → same handler, deprecated)

GET  /api/v1/repos/{repo_id}/scans
     → Scan history

GET  /api/v1/repos/{repo_id}/scans/{scan_id}
     → Scan status + results

POST /webhooks/github
     → GitHub App webhook receiver (no auth, validates HMAC signature)
```

### WebSocket (`/ws/`)

```
/ws/scans/{scan_id}
  → Real-time scan progress updates
  → Events: { "type": "progress", "module": "attack_surface", "step": "subfinder", "pct": 40 }
  → Events: { "type": "finding", "finding": {...} }
  → Events: { "type": "complete", "summary": {...} }
```

---

## 14. LLM Integration Layer

### Model Selection

**Primary:** `claude-sonnet-4-6` — best cost/quality tradeoff for structured JSON output  
**Fallback:** Configurable (GPT-4o as alternative for self-hosters who prefer OpenAI)

### Prompt Engineering Principles

1. **Structured output only** — always ask for JSON, validate with Pydantic before storing
2. **Bounded context** — never send full file, only relevant diff + targeted context (max 8k tokens)
3. **Few-shot examples** — include short **safe** vs **unsafe** pairs per category (access control + at least one non-auth class, e.g. secret in diff)
4. **Explicit false-positive instruction** — "Do not flag routes that are correctly protected. If you are unsure, do not flag."
5. **Chain-of-thought suppressed** — ask for JSON directly, no reasoning preamble (reduces tokens, reduces hallucinated explanations)

### Cost Controls

```python
MAX_TOKENS_PER_PR_REVIEW = 6000   # input
MAX_FINDINGS_PER_PR = 20          # truncate LLM output if more
ESTIMATED_COST_PER_REVIEW = 0.003  # ~$0.003 at Sonnet pricing

# If diff > 6000 tokens, chunk by file and review separately
# Prioritize files with route definitions over utility files
```

### LLM Response Validation

```python
class CodeSecurityFindingResponse(BaseModel):
    category: Literal[
        "access_control", "injection", "secrets", "ssrf",
        "deserialization", "crypto_tls", "other",
    ]
    issue_type: str
    route: Optional[str] = None
    method: Optional[str] = None
    file: str
    line: Optional[int] = None
    severity: Literal["critical", "high", "medium", "low"]
    cwe_id: Optional[int] = None
    explanation: str
    fix_suggestion: str

def parse_llm_response(raw: str) -> List[CodeSecurityFindingResponse]:
    cleaned = re.sub(r"```(?:json)?", "", raw).strip()
    data = json.loads(cleaned)
    return [CodeSecurityFindingResponse(**item) for item in data]
```

---

## 15. Dashboard & CLI

### Dashboard (Next.js 16)

**Pages:**
- `/` — Landing page (install CTA)
- `/dashboard` — Repo list with risk scores
- `/repos/{owner}/{name}` — Repo detail
  - `/repos/{owner}/{name}/surface` — Attack surface tab
  - `/repos/{owner}/{name}/deps` — Dependency risk tab
  - `/repos/{owner}/{name}/code-security` — LLM code security history (all categories); legacy `/auth` redirects
- `/repos/{owner}/{name}/scans/{id}` — Live scan view (WebSocket)

**Key design decisions:**
- Risk score prominently displayed: **0-100, color-coded** (green/yellow/orange/red)
- Attack surface visualized as a simple host table (not a graph — graphs are unreadable)
- Dep findings sorted by risk score, grouped by "Reachable / Not Reachable"
- Code security findings shown per-PR with category filter + link to GitHub PR comment

### CLI (`sentinel`)

The CLI is the **primary product surface** for local and agent-driven use. Hosted GitHub App flows post results to Check Runs and the web app; the same mental model applies: human-readable narrative + structured artifacts.

```bash
# Install
pip install sentinel-sec

# Authenticate (when using hosted/GitHub-backed features)
sentinel auth login   # opens browser → GitHub OAuth

# Commands
sentinel repos list
sentinel scan --repo org/repo [--domain SEED] [--stages ...] [--output DIR] [--quiet] [--no-dashboard]
sentinel report --repo org/repo [--format json|table|markdown] [--output file]
sentinel surface --repo org/repo [--live-only] [--severity high]
sentinel deps --repo org/repo [--reachable-only] [--fix]
sentinel pr --repo org/repo --pr 142
sentinel dashboard [--report DIR] [--port N]   # standalone; also auto-invoked after scan by default

# Demo mode (no auth required, uses sample data)
sentinel demo --repo torvalds/linux  # will obviously find nothing :)
```

#### `sentinel scan` behavior (normative)

| Mode | Terminal (stdout) | Dashboard | Artifacts |
|------|---------------------|-----------|-----------|
| **Default** | Rich progress + tables; LLM code-security rows include category + short rationale | Auto-start local server on `dashboard.port`, load `--output` report; browser if `auto_open` | Always written |
| **`--quiet` (`-q`)** | Suppressed (errors on stderr) | Not started | Always written |
| **`--no-dashboard`** | Same as default | Not started | Always written |

**LLM-native CLI:** Code security findings MUST render with: `category`, `issue_type`, `severity`, `cwe_id`, `location`, `summary` (LLM-generated, ≤ 240 chars), and `detail` in JSON/dashboard. This keeps logs useful for Cursor/Codex/CI log ingestion without opening HTML.

**Implementation notes:**
- Dashboard subprocess: reuse the same code path as `sentinel dashboard` (uvicorn/static server); scan blocks until scan work completes, then starts the dashboard in the **background**, prints the local URL, and returns the shell prompt (or keep foreground behind a `--dashboard-foreground` future flag if needed).
- `--quiet` always implies **no** auto-dashboard; stderr-only errors on top of artifact writes.

CLI uses `rich` for colorized table output and progress bars — looks good in terminal recordings for Twitter demos.

---

## 16. Security Architecture

### Secrets Management
- GitHub App private key: stored in env var, never in DB
- Installation access tokens: encrypted at rest (Fernet symmetric), short-lived (1hr), refreshed automatically
- User JWTs: RS256, 24hr expiry

### GitHub Permissions
- Minimum necessary: read-only on code, write on checks/PR comments
- No write access to repo contents

### Webhook Security
- All webhooks validated with `X-Hub-Signature-256` HMAC before processing
- Webhook secret stored in env, rotated on install

### Network
- Attack surface tools run in isolated Docker containers with no inbound internet access
- Outbound: only to GitHub API, OSV.dev API, Shodan API, Claude API
- No scanning of IPs/domains not tied to a tracked repo

### Data Isolation
- All repo data scoped by `installation_id` and `repo_id`
- API endpoints validate repo ownership before returning data
- Multi-tenant: one Sentinel instance can serve multiple GitHub App installations

---

## 17. Demo Strategy

**The goal: one scan, five findings, all dramatic.**

### Demo Target Selection

Ideal demo repos have:
- Real deployed infrastructure (not just "hello world")
- Active dependency usage (complex dep tree)
- Multiple API routes and a mix of safe and risky patterns (access control + at least one injectable or secret-adjacent path for demo contrast)
- Been around long enough to accumulate some CVEs

Good public demo candidates (pick one at launch):
- A popular open-source SaaS backend (think: Outline, Plane, Cal.com)
- Select based on: Python or Node backend, has `requirements.txt`/`package.json`, has deployed demo instance, active community

### Demo Script (for Twitter video)

```
1. "Let me run Sentinel on [repo]" — terminal, single `sentinel scan` (no second command)
2. Rich CLI: attack surface — 3 subdomains, 1 dangling CNAME → "this is takeover-able"
3. Rich CLI: dep risk — 2 reachable CVEs → show the call trace in the table
4. Rich CLI: code-security row (e.g. access control + one non-auth category) with short LLM rationale
5. Browser (auto-opened dashboard) — same findings, deeper triage view
```

### Demo Mode
- CLI has `--demo` flag that uses pre-baked realistic scan results
- Useful for conference demos where live network is unreliable

### Twitter Post Format
- Short video (<60s) of terminal + dashboard
- One punchy finding: "Found a dangling CNAME on [repo] — subdomain takeover possible"
- GitHub link to Sentinel repo

---

## 18. Infrastructure & Deployment

### Hosted SaaS

| Service | Provider | Notes |
|---------|----------|-------|
| API (FastAPI) | Railway | One service, auto-deploy from `main` |
| Celery workers | Railway | Separate Railway service, same repo/image |
| Celery beat | Railway | Separate Railway service for scheduler |
| PostgreSQL | Supabase | Managed Postgres, connection pooling via Supabase pooler |
| Redis | Upstash | Serverless Redis, pay-per-request, no idle cost |
| Dashboard (Next.js) | Vercel | Auto-deploy from `main`, edge CDN |

**Deploy flow:**
1. Push to `main` → Railway redeploys API + workers, Vercel redeploys dashboard
2. Supabase handles DB migrations via `supabase db push` in CI
3. GitHub App webhook URL points to Railway API service URL

**Railway services config (`railway.toml`):**
```toml
[services.api]
startCommand = "uvicorn sentinel.main:app --host 0.0.0.0 --port $PORT"

[services.worker]
startCommand = "celery -A sentinel.worker worker -Q high_priority,default,low_priority --concurrency 4"

[services.scheduler]
startCommand = "celery -A sentinel.worker beat --scheduler redbeat.RedBeatScheduler"
```

> Celery beat uses [redbeat](https://github.com/sibson/redbeat) so the schedule lives in Upstash Redis rather than a local file — safe for stateless Railway containers.

### Environment Variables

```env
# GitHub App (hosted API + workers only)
GITHUB_APP_ID=
GITHUB_APP_PRIVATE_KEY=   # base64-encoded PEM
GITHUB_WEBHOOK_SECRET=

# Database
DATABASE_URL=postgresql://...
REDIS_URL=redis://...

# External APIs
SHODAN_API_KEY=
ANTHROPIC_API_KEY=        # or OPENAI_API_KEY when llm.provider=openai

# Optional
OPENAI_API_KEY=
SLACK_WEBHOOK_URL=        # for critical CVE notifications
SMTP_URL=                 # for email notifications
```

#### Who configures what?

| Actor | What they do |
|-------|----------------|
| **Sentinel operator** (you run sentinel.dev or self-host) | Sets **all** variables in the table below for API + worker + scheduler services (Railway, Docker, etc.). End users never paste `GITHUB_APP_PRIVATE_KEY`. |
| **Customer installing the GitHub App** | **No env vars.** They authorize the App in GitHub’s UI; OAuth/installation grants scope. Optional future: BYOK LLM key or org Shodan key in a settings screen — not required for v1. |
| **CLI user** (`pip install` on a laptop or CI) | Only the keys for the **stages they run** (see matrix). Use a shell, `.env` loaded by the CLI, or CI secrets — never commit secrets into `sentinel.yml`. |

#### Required vs optional (by deployment)

**A) Hosted Sentinel (FastAPI + Celery — one operator deployment)**

| Variable | Required? | If missing |
|----------|-----------|------------|
| `GITHUB_APP_ID` | **Yes** | Cannot verify webhooks or call GitHub as the App |
| `GITHUB_APP_PRIVATE_KEY` | **Yes** | Cannot mint installation tokens |
| `GITHUB_WEBHOOK_SECRET` | **Yes** | Must reject unsigned webhooks (or dev-only bypass behind explicit flag) |
| `DATABASE_URL` | **Yes** | No findings persistence, installs, or multi-tenant state |
| `REDIS_URL` | **Yes** | No Celery queue / RedBeat schedule |
| `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` | **Yes** for PR / code-security workers | LLM jobs fail; other workers may still run |
| `SHODAN_API_KEY` | **No** (recommended) | Attack-surface stage degrades: skip or reduce Shodan-backed host/port enrichment |
| `SLACK_WEBHOOK_URL`, `SMTP_URL` | **No** | No outbound notifications |

**B) Local CLI only (no App, no your SaaS backend)**

| Variable | Required? | If missing |
|----------|-----------|------------|
| `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` | **Yes** if `code_security` enabled (alias: `auth_review`) | Code security stage errors or skips with clear message |
| `GITHUB_TOKEN` | **No** for public `git clone` / API | **Yes** for private repos or higher rate limits |
| `SHODAN_API_KEY` | **No** | Weaker or empty Shodan-based surface signals; Subfinder/DNS paths still work where no key is needed |
| App/DB/Redis vars | **Not used** | — |

**C) GitHub Actions using `sentinel scan`**

Same as **B**, but secrets live in the repo/org **Actions secrets** (e.g. `ANTHROPIC_API_KEY`, optional `SHODAN_API_KEY`, `GITHUB_TOKEN` is usually automatic via `permissions:`).

---

## 19. Future Work

### v2 Features

| Feature | Description |
|---------|-------------|
| **Hosted public scanner** | From sentinel.dev: queue scans of public repo URLs without local CLI (rate-limited, abuse controls; distinct from GitHub App install) |
| **Org-wide view** | Single dashboard for all repos in a GitHub org, rolled-up risk score |
| **Go / Rust / Java support** | Extend dep analysis to more ecosystems |
| **Deeper secret scanning** | Git history / blob-level trufflehog-style beyond diff-only (v1 covers diff + deterministic entropy hints) |
| **SBOM export** | Generate CycloneDX/SPDX SBOM from dep analysis |
| **Jira/Linear integration** | Auto-create tickets for critical findings |
| **Slack App** | `/sentinel scan org/repo` in Slack |
| **Historical tracking** | Risk score over time, "did you get better or worse?" |
| **Active attack surface** | Optional: nmap scan (with explicit user consent) for more complete port data |
| **Full call graph** | Interprocedural reachability for Python (using `pycg`) |
| **Custom rules** | User-defined middleware patterns and org-specific banned APIs |

### v3 Vision ("find 5 vulnerable repos on Twitter")
- Public database of Sentinel scan results for popular open-source repos
- Anonymized findings shared with repo owners via responsible disclosure
- Opt-in public trust score: "This repo has been scanned by Sentinel: risk score 23/100"

---

## Appendix: Key Technology Choices Rationale

| Decision | Choice | Why |
|----------|--------|-----|
| GitHub App vs Actions | App | One-click install, no repo commit needed, better UX |
| App install vs CLI | Both | App gates **hosted** automation; **local CLI** may scan any repo the user can read (G9 / NG5) |
| OSV.dev vs Snyk | OSV.dev | Free, open, machine-readable, no rate limits on bulk |
| Cache CVEs vs live | Cache (24hr) | Latency: 150 pkgs × 200ms = 30s unacceptable |
| tree-sitter vs regex | tree-sitter | Correct AST parsing, handles edge cases, multi-language |
| Claude vs GPT-4 | Claude (configurable) | Better instruction-following for structured JSON; configurable |
| Subfinder vs Amass | Subfinder | Faster for passive recon; add Amass as optional enhancement |
| Shodan vs active scan | Shodan | Passive, legal, no rate-limit concerns, instant |
| FastAPI vs Django | FastAPI | Async, WebSocket support, Pydantic validation built-in |
| Celery vs asyncio | Celery | Distributed workers, retries, scheduling — production-grade |

---

## 20. Implementation Phases & Milestone Plan

### Phase 1 — CLI MVP (target: first public demo)

**Goal:** `sentinel scan` works end-to-end on a public repo from a laptop. Single `pip install`. No database, no GitHub App, no hosted infra required.

**Deliverables:**

| Component | Key files/modules | Acceptance criteria |
|-----------|------------------|---------------------|
| CLI entrypoint | `sentinel/cli.py` (Click), `sentinel/scan.py` | `sentinel scan --repo <url>` runs all 3 stages, exits 0 or 1 based on `--fail-on` |
| Attack surface module | `sentinel/modules/surface.py`, subprocess wrappers for subfinder/httpx | Returns `List[AttackSurfaceFinding]` for a known domain with ≥1 real subdomain |
| Dependency risk module | `sentinel/modules/deps.py`, `sentinel/parsers/*.py` | Parses `requirements.txt` + `package.json`; returns scored findings against real OSV data |
| LLM code security module | `sentinel/modules/code_security.py`, `sentinel/llm.py` | Reviews a known-vulnerable diff; returns ≥1 `CodeSecurityFinding` with correct category |
| Unified findings writer | `sentinel/report.py` | Writes `findings.json` that passes `UnifiedReport` Pydantic validation |
| Rich CLI output | `sentinel/display.py` | Terminal shows progress bars + per-stage summary tables; `--quiet` suppresses all |
| Local dashboard server | `sentinel/dashboard_server.py` | `sentinel dashboard` serves static Next.js build on port 4000; auto-opens browser when `auto_open: true` |
| `sentinel.yml` config | `sentinel/config.py` | Loads config, merges env vars, validates with Pydantic; missing LLM key → clear error |

**Phase 1 is complete when:** `sentinel scan --repo https://github.com/owner/public-repo` produces a Rich terminal report, writes `findings.json`, and opens a browser dashboard — all from a fresh `pip install sentinel-sec`.

---

### Phase 2 — GitHub App + Webhooks (target: closed beta)

**Goal:** Install the GitHub App on a repo and get automatic PR reviews + nightly surface scans with zero CLI interaction.

**New components:**

| Component | Key files/modules | Acceptance criteria |
|-----------|------------------|---------------------|
| FastAPI webhook receiver | `sentinel/api/webhooks.py` | Validates HMAC, routes event types, enqueues correct Celery task within 500ms |
| Celery workers | `sentinel/workers/*.py` + `railway.toml` | All three scan workers run in separate Railway services; task dedup prevents double-scans |
| PostgreSQL persistence | `sentinel/db/models.py`, Alembic migrations | All finding types stored; scan history queryable; multi-tenant isolation passes test |
| GitHub Check Run poster | `sentinel/github/checks.py` | PR review findings appear as inline annotations within 60s of PR open |
| GitHub OAuth flow | `sentinel/api/auth.py` | User can install App and log into dashboard via GitHub OAuth |
| Hosted dashboard | `dashboard/` (Next.js) deployed to Vercel | Shows live findings for an installed repo; WebSocket scan progress works |
| Nightly CVE sync | `sentinel/workers/cve_sync.py` | Runs at 3am UTC via RedBeat; invalidates stale Redis cache entries; alerts on CVSS ≥ 9.0 |

**Phase 2 is complete when:** A developer opens a PR on a GitHub App-installed repo and sees Sentinel Check Run annotations within 60 seconds.

---

### Phase 3 — Hosted SaaS (target: public launch)

**Goal:** sentinel.dev is publicly available. Any user can install the App, get a dashboard, and share a repo risk score.

**New components:**

| Component | Key files/modules | Acceptance criteria |
|-----------|------------------|---------------------|
| Billing / usage tracking | `sentinel/api/billing.py` | Usage metered by scan count; LLM cost tracked per org |
| Org-level dashboard | `dashboard/app/orgs/` | Rolls up risk scores across all repos in a GitHub org |
| Email notifications | `sentinel/notifications/email.py` | Critical CVE alert email delivered within 5min of nightly sync |
| Rate limiting | Redis-backed per-install limits | No single install can consume > 20% of worker capacity |
| Observability | OpenTelemetry → Grafana/Honeycomb | P95 PR review latency tracked; alerts at > 90s |
| Demo mode | `sentinel scan --demo` | Pre-baked scan results usable offline for conference demos |

---

## 21. Testing Strategy

### Principles

1. **Real over mock where feasible.** OSV.dev and Claude API calls are mocked for unit tests but integration tests run against live APIs in a controlled fixture. This avoids the class of bugs where mocked behavior diverges from production.
2. **Fixture-pinned for determinism.** Vulnerability fixtures use pinned OSV snapshots; diff fixtures use real historical commits from public repos. Tests do not make live GitHub API calls.
3. **Fast vs full suites.** `pytest -m fast` (<30s) runs in CI on every push. `pytest -m integration` runs nightly or on `main` merge.

---

### Unit Tests — Module Coverage

**Attack Surface (`tests/test_surface.py`):**

```python
# Test dangling CNAME detection without network I/O
def test_is_dangling_s3(monkeypatch):
    monkeypatch.setattr("sentinel.modules.surface.check_s3_bucket_exists", lambda _: False)
    assert is_dangling("old-assets.s3.amazonaws.com") is True

def test_is_not_dangling_active_heroku(monkeypatch):
    monkeypatch.setattr("sentinel.modules.surface.check_heroku_app_exists", lambda _: True)
    assert is_dangling("myapp.herokuapp.com") is False

# Test domain extraction from repo config files
def test_parse_repo_for_domains_docker_compose(tmp_path):
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  api:\n    environment:\n      - BASE_URL=https://api.example.com\n"
    )
    domains = parse_repo_for_domains(str(tmp_path))
    assert "example.com" in domains
```

**Dependency Risk (`tests/test_deps.py`):**

```python
# Test scoring with a reachable, known-exploit CVE
def test_score_reachable_exploit():
    vuln = Vulnerability(cvss_score=8.5, has_known_exploit=True)
    reach = ReachabilityResult(is_reachable=True, depth=0)
    score = score_dependency(pkg, [vuln], reach)
    assert score == pytest.approx(8.5 * 1.0 * 1.0 * 1.3, rel=1e-3)

# Test that unreachable dep gets 0.2x multiplier
def test_score_unreachable_dep():
    vuln = Vulnerability(cvss_score=9.0, has_known_exploit=False)
    reach = ReachabilityResult(is_reachable=False, depth=0)
    score = score_dependency(pkg, [vuln], reach)
    assert score < 2.0  # 9.0 * 0.2 = 1.8

# Test lockfile parsers
def test_parse_requirements_txt(fixture_path):
    pkgs = parse_requirements_txt(fixture_path / "requirements.txt")
    assert any(p.name == "requests" and p.version == "2.26.0" for p in pkgs)

def test_parse_package_json(fixture_path):
    pkgs = parse_package_json(fixture_path / "package.json")
    assert any(p.name == "axios" for p in pkgs)
```

**LLM Code Security (`tests/test_code_security.py`):**

```python
# Test LLM response parsing
def test_parse_llm_response_valid():
    raw = '[{"category": "access_control", "issue_type": "missing_auth", "file": "routes.py", "line": 42, "severity": "high", "explanation": "No auth dependency on admin route", "fix_suggestion": "Add Depends(get_current_user)"}]'
    findings = parse_llm_response(raw)
    assert len(findings) == 1
    assert findings[0].category == "access_control"

def test_parse_llm_response_empty():
    assert parse_llm_response("[]") == []

def test_parse_llm_response_wrapped_json():
    raw = "```json\n[]\n```"
    assert parse_llm_response(raw) == []

# Test framework detection
def test_detect_framework_fastapi(repo_fixture):
    assert detect_framework(repo_fixture / "fastapi_app") == "fastapi"

def test_detect_framework_express(repo_fixture):
    assert detect_framework(repo_fixture / "express_app") == "express"
```

---

### Integration Tests (`tests/integration/`)

Run with `pytest -m integration`. Require live API keys set in env.

**OSV Integration (`tests/integration/test_osv.py`):**

```python
@pytest.mark.integration
def test_osv_query_known_vuln():
    """requests 2.26.0 has CVE-2023-32681 — must be returned by OSV."""
    vulns = query_osv("PyPI", "requests", "2.26.0")
    assert any(v.id == "GHSA-j8r2-6x86-q33q" for v in vulns)

@pytest.mark.integration
def test_osv_cache_hit(redis_client):
    """Second query for same package hits Redis, not OSV API."""
    query_osv("PyPI", "requests", "2.26.0")  # warms cache
    with patch("sentinel.modules.deps.fetch_from_osv_api") as mock:
        query_osv("PyPI", "requests", "2.26.0")
        mock.assert_not_called()
```

**LLM Integration (`tests/integration/test_llm.py`):**

```python
@pytest.mark.integration
def test_llm_catches_missing_auth(anthropic_api_key):
    """Synthetic diff with unprotected admin route must produce access_control finding."""
    diff = load_fixture("diffs/missing_auth_admin_route.diff")
    middleware_ctx = load_fixture("context/fastapi_auth_middleware.py")
    findings = run_llm_code_review(diff, middleware_ctx)
    assert any(f.category == "access_control" for f in findings)
    assert all(f.severity in ("critical", "high", "medium", "low") for f in findings)

@pytest.mark.integration
def test_llm_no_false_positive_protected_route(anthropic_api_key):
    """Route correctly using Depends(get_current_user) must produce no findings."""
    diff = load_fixture("diffs/correctly_protected_route.diff")
    middleware_ctx = load_fixture("context/fastapi_auth_middleware.py")
    findings = run_llm_code_review(diff, middleware_ctx)
    assert findings == []
```

**GitHub Webhook Integration (`tests/integration/test_webhooks.py`):**

```python
@pytest.mark.integration
def test_webhook_pr_enqueues_review(test_client, celery_worker):
    payload = load_fixture("webhooks/pull_request_opened.json")
    sig = compute_hmac(payload, TEST_WEBHOOK_SECRET)
    resp = test_client.post(
        "/webhooks/github",
        content=payload,
        headers={"X-GitHub-Event": "pull_request", "X-Hub-Signature-256": sig},
    )
    assert resp.status_code == 202
    assert celery_worker.tasks_enqueued("pr_review") == 1
```

---

### E2E Test: Known-Findings Scan

A pinned public repo with documented findings serves as a regression canary:

```bash
# Runs nightly in CI against pinned commit SHA
sentinel scan \
  --repo https://github.com/sentinel-fixtures/test-vulnerable-app \
  --commit abc123def \
  --quiet \
  --format json \
  --output /tmp/e2e-report

# Assert specific findings exist in output
python scripts/assert_findings.py /tmp/e2e-report/findings.json \
  --expect-category access_control \
  --expect-package requests@2.26.0 \
  --expect-host staging.test-app.example.com
```

---

### CI Matrix

```yaml
# .github/workflows/ci.yml (relevant excerpt)
strategy:
  matrix:
    python-version: ["3.11", "3.12"]
    test-suite: ["fast", "integration"]
    exclude:
      - test-suite: integration
        python-version: "3.11"   # integration only on 3.12

steps:
  - run: pytest tests/ -m ${{ matrix.test-suite }} --timeout=120
    env:
      ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY_TEST }}
      REDIS_URL: redis://localhost:6379
      DATABASE_URL: postgresql://test:test@localhost/sentinel_test
```

---

## 22. Agent Context & Memory Architecture

### The Core Problem

A naive LLM reviewer dumps the entire repo into the context window — expensive, slow, and often counterproductive (the model loses focus). Sentinel's approach: **bounded, structured context packs** assembled deterministically before each LLM call.

### Context Pack Architecture

```
PR Diff
  │
  ▼
┌──────────────────────────────────────────┐
│  ContextPackBuilder                       │
│                                          │
│  1. diff_hunks      (always included)    │
│  2. route_list      (from AST)           │
│  3. middleware_excerpt (top 100 lines)   │
│  4. similar_safe_patterns (few-shot)     │
│  5. secrets_prepass_hits (deterministic) │
│                                          │
│  Token budget: MAX_TOKENS_PER_PR_REVIEW  │
│  = 6000 input tokens                    │
│                                          │
│  Priority order when budget is tight:    │
│    route files > handler files > utils   │
└──────────────────────────────────────────┘
```

```python
@dataclass
class ContextPack:
    diff_hunks: List[DiffHunk]           # always present
    routes: List[RouteSignal]            # extracted by tree-sitter
    middleware_excerpt: str              # top N lines of auth middleware
    safe_pattern_examples: List[str]     # correctly-protected routes for few-shot
    prepass_hits: List[PrepassHit]       # deterministic regex/entropy hits
    framework: str                       # "fastapi" | "express" | "django" | ...
    token_count: int                     # estimated before sending

def build_context_pack(
    diff: ParsedDiff,
    repo_path: str,
    framework: str,
    budget: int = MAX_TOKENS_PER_PR_REVIEW,
) -> ContextPack:
    routes = extract_routes_from_diff(diff, framework)
    middleware = find_auth_middleware(repo_path, framework)
    safe_examples = find_safe_route_examples(repo_path, routes, n=3)
    prepass = run_secrets_prepass(diff)
    return ContextPack(
        diff_hunks=prioritized_hunks(diff, routes, budget),
        routes=routes,
        middleware_excerpt=middleware[:2000],  # chars
        safe_pattern_examples=safe_examples,
        prepass_hits=prepass,
        framework=framework,
        token_count=estimate_tokens(...),
    )
```

### Memory: Avoiding Repeated False Positives

The biggest signal/noise problem for LLM code review is **repeated findings on the same pattern** across PRs. If a codebase consistently uses `yaml.safe_load` everywhere and the LLM keeps flagging it, developers tune out.

**v1 approach: Per-repo finding suppression table**

```sql
CREATE TABLE suppressed_patterns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repo_id UUID REFERENCES repos(id),
    category TEXT NOT NULL,
    issue_type TEXT NOT NULL,
    pattern_hash TEXT NOT NULL,  -- hash of (file_path_glob + code_fragment)
    suppressed_by TEXT,          -- 'user' | 'auto' (>3 false positive marks)
    reason TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

Before posting a finding, check:
```python
def is_suppressed(finding: CodeSecurityFinding, repo_id: str) -> bool:
    pattern_hash = hash_finding_pattern(finding)
    return db.exists(
        "SELECT 1 FROM suppressed_patterns WHERE repo_id=$1 AND pattern_hash=$2",
        repo_id, pattern_hash,
    )
```

**Auto-suppression:** When 3+ developers mark the same finding pattern as "false positive" across different PRs, Sentinel auto-creates a suppression entry and reduces future noise from that pattern.

### Context Retrieval for Large Repos

For repos with > 500 files, loading all middleware and route context is too slow. Use a lightweight **inverted index** over the repo at baseline scan time:

```python
@dataclass
class RepoIndex:
    route_files: List[str]          # files containing route definitions
    middleware_files: List[str]     # files containing auth/guard patterns
    sink_files: List[str]           # files with high-risk sinks (exec, query, fetch)
    framework: str
    indexed_at: datetime

# Built once at baseline scan, stored in Redis with 24hr TTL
# key: repo_index:{repo_id}:{commit_sha}
```

When a PR comes in, fetch the index to know which files to pull for context without scanning the whole repo tree.

### Signal/Noise Reduction Roadmap

| Phase | Approach | Mechanism |
|-------|----------|-----------|
| **v1** | Explicit suppression list + false-positive feedback | `suppressed_patterns` table, user "mark as false positive" in dashboard |
| **v1.5** | Category-level confidence calibration | Track precision per `(category, framework)` pair; down-weight low-precision combos in ranking |
| **v2** | Retrieval-augmented few-shot | Build a library of confirmed true/false positives per repo; inject as few-shot examples at review time |
| **v3 (RL)** | Reward signal from developer actions | PR fix = positive signal, "close without fix" = weak negative; fine-tune embedding model for context retrieval |

---

## 23. Module Interfaces & Internal API Contracts

This section defines the internal contracts between the three analysis modules and the normalization layer that produces a single findings stream for storage, API delivery, and dashboard rendering.

### 23.1 Design Principles

- Each module returns a typed, module-specific result first.
- Normalization into `UnifiedFinding` happens in a dedicated adapter layer, not inside the scanning logic.
- Partial failure is expected. A scan may complete with findings from one or two modules even if another dependency or provider is unavailable.
- External tool and API failures are captured as structured scan events and module errors, not only thrown exceptions.

### 23.2 Module Boundaries

```text
repo clone / diff / config
  -> Attack Surface module
  -> Dependency Risk module
  -> Code Security module
  -> normalize_* adapters
  -> List[UnifiedFinding]
  -> persistence + API + dashboard + GitHub reporting
```

### 23.3 Core Runtime Types

```python
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, Optional, Protocol, Sequence
from uuid import UUID


Severity = Literal["critical", "high", "medium", "low", "info"]
ModuleName = Literal["attack_surface", "dep_risk", "code_security"]
FindingKind = Literal["surface", "dependency", "code"]
ScanStatus = Literal["pending", "running", "completed", "partial", "failed", "skipped"]


@dataclass(slots=True)
class RepoRef:
    repo_id: UUID
    owner: str
    name: str
    default_branch: str
    clone_path: Path


@dataclass(slots=True)
class PRContext:
    pr_number: int
    base_sha: str
    head_sha: str
    changed_files: list[str]


@dataclass(slots=True)
class ScanContext:
    scan_id: UUID
    trigger: Literal["push", "pr", "scheduled", "manual", "cli"]
    started_at: datetime
    repo: RepoRef
    pr: Optional[PRContext] = None
    requested_modules: list[ModuleName] = field(default_factory=list)
    domain_seeds: list[str] = field(default_factory=list)
    correlation_id: Optional[str] = None
```

### 23.4 Module Protocols

```python
class AttackSurfaceModule(Protocol):
    def run(self, ctx: ScanContext) -> "AttackSurfaceResult": ...


class DependencyRiskModule(Protocol):
    def run(self, ctx: ScanContext) -> "DependencyRiskResult": ...


class CodeSecurityModule(Protocol):
    def run(self, ctx: ScanContext) -> "CodeSecurityResult": ...
```

### 23.5 Module 1: Attack Surface Interfaces

```python
@dataclass(slots=True)
class TLSInfo:
    issuer: Optional[str]
    subject: Optional[str]
    san_hosts: list[str]
    expires_at: Optional[datetime]
    supports_tls_1_0: bool
    supports_tls_1_1: bool
    supports_tls_1_2: bool
    supports_tls_1_3: bool
    weak_ciphers: list[str]


@dataclass(slots=True)
class SurfaceIssue:
    type: Literal[
        "dangling_cname",
        "expired_cert",
        "tls_weak_cipher",
        "open_port",
        "missing_hsts",
        "weak_dmarc",
        "missing_csp",
        "service_banner_exposed",
    ]
    severity: Severity
    detail: str
    cve: Optional[str] = None
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class AttackSurfaceFinding:
    repo_id: UUID
    scan_id: UUID
    host: str
    ip: Optional[str]
    status: Literal["live", "dead", "dangling"]
    ports: list[int]
    tls: Optional[TLSInfo]
    technologies: list[str]
    issues: list[SurfaceIssue]
    discovered_via: Literal["repo_scan", "subfinder", "cert_san", "shodan", "manual_seed"]
    first_seen: datetime
    last_seen: datetime


@dataclass(slots=True)
class ModuleError:
    module: ModuleName
    stage: str
    message: str
    retryable: bool
    provider: Optional[str] = None
    exit_code: Optional[int] = None
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class AttackSurfaceResult:
    status: ScanStatus
    findings: list[AttackSurfaceFinding]
    errors: list[ModuleError]
    stats: dict[str, Any]


def parse_repo_for_domains(repo_path: Path) -> set[str]: ...
def enumerate_subdomains(domains: Sequence[str]) -> list[str]: ...
def probe_http_hosts(hosts: Sequence[str]) -> list[dict[str, Any]]: ...
def enrich_with_shodan(hosts: Sequence[str]) -> dict[str, dict[str, Any]]: ...
def analyze_dns(host: str) -> list[SurfaceIssue]: ...
def analyze_tls(host_probe: dict[str, Any]) -> Optional[TLSInfo]: ...
def build_surface_findings(
    ctx: ScanContext,
    probes: Sequence[dict[str, Any]],
    shodan_data: dict[str, dict[str, Any]],
) -> list[AttackSurfaceFinding]: ...
```

### 23.6 Module 2: Dependency Risk Interfaces

```python
@dataclass(slots=True)
class CVERef:
    osv_id: str
    aliases: list[str]
    summary: str
    cvss_score: Optional[float]
    has_known_exploit: bool
    fixed_versions: list[str]
    vulnerable_functions: list[str]
    references: list[str]


@dataclass(slots=True)
class PackageRef:
    ecosystem: Literal["PyPI", "npm"]
    package_name: str
    version: str
    is_direct: bool
    manifest_path: str
    transitive_chain: list[str]


@dataclass(slots=True)
class ReachabilityResult:
    is_reachable: bool
    partial: bool = False
    depth: int = 0
    trace: Optional[str] = None
    reason: Optional[str] = None


@dataclass(slots=True)
class DepRiskFinding:
    package_name: str
    version: str
    ecosystem: str
    risk_score: float
    cvss_max: float
    vulns: list[CVERef]
    is_reachable: bool
    reachability_trace: Optional[str]
    is_direct: bool
    transitive_chain: list[str]
    fix_version: Optional[str]
    fix_available: bool
    patch_lag_days: Optional[int]


@dataclass(slots=True)
class DependencyRiskResult:
    status: ScanStatus
    findings: list[DepRiskFinding]
    errors: list[ModuleError]
    stats: dict[str, Any]


def discover_packages(repo_path: Path) -> list[PackageRef]: ...
def query_osv(package: PackageRef) -> list[CVERef]: ...
def query_osv_batch(packages: Sequence[PackageRef]) -> dict[str, list[CVERef]]: ...
def check_python_reachability(
    repo_path: Path,
    package: str,
    vuln_functions: Sequence[str],
) -> ReachabilityResult: ...
def check_js_reachability(
    repo_path: Path,
    package: str,
    vuln_functions: Sequence[str],
) -> ReachabilityResult: ...
def score_dependency(
    pkg: PackageRef,
    vulns: Sequence[CVERef],
    reachability: ReachabilityResult,
) -> float: ...
def build_dep_findings(
    packages: Sequence[PackageRef],
    osv_results: dict[str, list[CVERef]],
    repo_path: Path,
) -> list[DepRiskFinding]: ...
```

### 23.7 Module 3: Code Security Interfaces

```python
@dataclass(slots=True)
class DiffHunk:
    file: str
    added_lines: list[int]
    deleted_lines: list[int]
    patch: str


@dataclass(slots=True)
class RouteContext:
    file: str
    route: Optional[str]
    method: Optional[str]
    framework: Optional[str]
    auth_signals: list[str]
    sink_signals: list[str]


@dataclass(slots=True)
class PromptPack:
    system_prompt: str
    user_prompt: str
    route_contexts: list[RouteContext]
    diff_hunks: list[DiffHunk]
    token_estimate: int


@dataclass(slots=True)
class CodeSecurityFinding:
    category: Literal[
        "access_control",
        "injection",
        "secrets",
        "ssrf",
        "deserialization",
        "crypto_tls",
        "other",
    ]
    issue_type: str
    route: Optional[str]
    method: Optional[str]
    file: str
    line: Optional[int]
    severity: Literal["critical", "high", "medium", "low"]
    cwe_id: Optional[int]
    explanation: str
    fix_suggestion: str
    pr_number: int
    commit_sha: str
    reviewed_at: datetime
    llm_model: str
    prompt_tokens: int
    completion_tokens: int


@dataclass(slots=True)
class CodeSecurityResult:
    status: ScanStatus
    findings: list[CodeSecurityFinding]
    errors: list[ModuleError]
    stats: dict[str, Any]


def collect_diff_context(repo_path: Path, pr: PRContext) -> list[DiffHunk]: ...
def detect_framework(repo_path: Path) -> Optional[str]: ...
def extract_route_contexts(repo_path: Path, hunks: Sequence[DiffHunk]) -> list[RouteContext]: ...
def build_prompt_pack(
    ctx: ScanContext,
    hunks: Sequence[DiffHunk],
    routes: Sequence[RouteContext],
) -> PromptPack: ...
def review_with_llm(prompt: PromptPack) -> list[CodeSecurityFinding]: ...
def post_pr_review(pr: PRContext, findings: Sequence[CodeSecurityFinding]) -> None: ...
```

### 23.8 Normalization Layer and UnifiedFinding Schema

The three modules emit different native shapes. The API, dashboard, exports, and persistence layer consume one normalized schema.

```python
@dataclass(slots=True)
class UnifiedFinding:
    finding_id: str
    scan_id: UUID
    repo_id: UUID
    module: ModuleName
    kind: FindingKind
    title: str
    severity: Severity
    confidence: Literal["high", "medium", "low"]
    summary: str
    evidence: dict[str, Any]
    location: dict[str, Any]
    asset: dict[str, Any]
    remediation: dict[str, Any]
    source_refs: list[str]
    tags: list[str]
    raw: dict[str, Any]
    created_at: datetime
```

#### Normalization adapters

```python
def normalize_surface_finding(f: AttackSurfaceFinding) -> list[UnifiedFinding]:
    findings: list[UnifiedFinding] = []
    for issue in f.issues:
        findings.append(
            UnifiedFinding(
                finding_id=f"surface:{f.host}:{issue.type}",
                scan_id=f.scan_id,
                repo_id=f.repo_id,
                module="attack_surface",
                kind="surface",
                title=f"{issue.type.replace('_', ' ').title()} on {f.host}",
                severity=issue.severity,
                confidence="high",
                summary=issue.detail,
                evidence=issue.evidence,
                location={"host": f.host, "ip": f.ip, "ports": f.ports},
                asset={"host": f.host, "status": f.status, "technologies": f.technologies},
                remediation={"action": issue.type, "fix_version": None},
                source_refs=[f.discovered_via],
                tags=["attack-surface", issue.type],
                raw={"finding": f, "issue": issue},
                created_at=f.last_seen,
            )
        )
    return findings


def normalize_dep_finding(ctx: ScanContext, f: DepRiskFinding) -> UnifiedFinding:
    top_vuln = max(f.vulns, key=lambda v: v.cvss_score or 0.0)
    return UnifiedFinding(
        finding_id=f"dep:{f.ecosystem}:{f.package_name}:{f.version}",
        scan_id=ctx.scan_id,
        repo_id=ctx.repo.repo_id,
        module="dep_risk",
        kind="dependency",
        title=f"Reachable vulnerable dependency: {f.package_name}",
        severity="critical" if f.risk_score >= 9 else "high" if f.risk_score >= 7 else "medium",
        confidence="high" if f.is_reachable else "medium",
        summary=top_vuln.summary,
        evidence={
            "risk_score": f.risk_score,
            "cvss_max": f.cvss_max,
            "reachability_trace": f.reachability_trace,
        },
        location={"manifest": None, "package": f.package_name},
        asset={"ecosystem": f.ecosystem, "package": f.package_name, "version": f.version},
        remediation={"fix_version": f.fix_version, "fix_available": f.fix_available},
        source_refs=[v.osv_id for v in f.vulns],
        tags=["dependency", f.ecosystem.lower()],
        raw={"finding": f},
        created_at=datetime.utcnow(),
    )


def normalize_code_finding(ctx: ScanContext, f: CodeSecurityFinding) -> UnifiedFinding:
    return UnifiedFinding(
        finding_id=f"code:{f.commit_sha}:{f.file}:{f.line}:{f.issue_type}",
        scan_id=ctx.scan_id,
        repo_id=ctx.repo.repo_id,
        module="code_security",
        kind="code",
        title=f.issue_type.replace('_', ' ').title(),
        severity=f.severity,
        confidence="medium",
        summary=f.explanation,
        evidence={"cwe_id": f.cwe_id, "route": f.route, "method": f.method},
        location={"file": f.file, "line": f.line, "route": f.route, "method": f.method},
        asset={"pr_number": f.pr_number, "commit_sha": f.commit_sha},
        remediation={"suggestion": f.fix_suggestion},
        source_refs=[f"pr:{f.pr_number}", f.llm_model],
        tags=["code-security", f.category, f.issue_type],
        raw={"finding": f},
        created_at=f.reviewed_at,
    )
```

### 23.9 Data Flow Between Modules

```text
Attack Surface:
  repo/config/domain seeds
  -> parse_repo_for_domains()
  -> enumerate_subdomains()
  -> probe_http_hosts()
  -> analyze_dns() + analyze_tls() + enrich_with_shodan()
  -> List[AttackSurfaceFinding]
  -> normalize_surface_finding()
  -> List[UnifiedFinding]

Dependency Risk:
  repo clone
  -> discover_packages()
  -> query_osv_batch()
  -> check_*_reachability()
  -> score_dependency()
  -> List[DepRiskFinding]
  -> normalize_dep_finding()
  -> List[UnifiedFinding]

Code Security:
  repo clone + PR diff
  -> collect_diff_context()
  -> extract_route_contexts()
  -> build_prompt_pack()
  -> review_with_llm()
  -> List[CodeSecurityFinding]
  -> normalize_code_finding()
  -> List[UnifiedFinding]
```

The orchestrator merges all normalized outputs in scan order:

```python
def run_scan(ctx: ScanContext, services: "ServiceContainer") -> list[UnifiedFinding]:
    unified: list[UnifiedFinding] = []

    if "attack_surface" in ctx.requested_modules:
        surface = services.attack_surface.run(ctx)
        for finding in surface.findings:
            unified.extend(normalize_surface_finding(finding))

    if "dep_risk" in ctx.requested_modules:
        deps = services.dep_risk.run(ctx)
        for finding in deps.findings:
            unified.append(normalize_dep_finding(ctx, finding))

    if "code_security" in ctx.requested_modules and ctx.pr is not None:
        code = services.code_security.run(ctx)
        for finding in code.findings:
            unified.append(normalize_code_finding(ctx, finding))

    return unified
```

### 23.10 Error Handling Patterns

Sentinel uses typed, stage-aware failure handling.

#### Error taxonomy

```python
class SentinelError(Exception):
    retryable: bool = False
    stage: str = "unknown"


class ExternalToolError(SentinelError):
    retryable = True


class ExternalAPIError(SentinelError):
    retryable = True


class ConfigError(SentinelError):
    retryable = False


class ValidationError(SentinelError):
    retryable = False
```

#### Pattern: subfinder fails

- If `subfinder` exits non-zero, record a `ModuleError` with `provider="subfinder"`.
- Continue with repo-derived domains, DNS checks, and any already-known SAN hosts.
- Module status becomes `partial`, not `failed`, unless no other discovery path is available.

```python
def enumerate_subdomains(domains: Sequence[str]) -> list[str]:
    try:
        return run_subfinder(domains)
    except ExternalToolError as exc:
        record_module_error(
            ModuleError(
                module="attack_surface",
                stage="subdomain_enumeration",
                provider="subfinder",
                message=str(exc),
                retryable=True,
            )
        )
        return []
```

#### Pattern: OSV is down

- First consult Redis and PostgreSQL warm cache.
- If cache hit exists, continue and mark source as stale-but-usable.
- If no cache and OSV is unavailable, produce no new dependency findings for affected packages, attach a module error, and mark module `partial`.

```python
def query_osv(package: PackageRef) -> list[CVERef]:
    cached = get_cached_osv(package)
    if cached is not None:
        return cached
    try:
        result = fetch_osv_live(package)
    except ExternalAPIError as exc:
        raise ExternalAPIError(
            f"OSV lookup failed for {package.package_name}@{package.version}: {exc}"
        ) from exc
    cache_osv(package, result)
    return result
```

#### Pattern: Claude API errors

- Retry on rate limit, timeout, or 5xx with bounded exponential backoff (3 attempts).
- Reprompt once with stricter JSON repair instructions on schema-invalid response; then fail module as `partial`.
- PR Check Run should report `"scan completed with code security unavailable"` rather than silently passing.

```python
def review_with_llm(prompt: PromptPack) -> list[CodeSecurityFinding]:
    for attempt in range(3):
        try:
            raw = anthropic_client.messages.create(...)
            return parse_llm_response(raw)
        except RateLimitError:
            sleep(2 ** attempt)
        except TimeoutError:
            sleep(2 ** attempt)
        except json.JSONDecodeError:
            if attempt == 0:
                prompt = rebuild_repair_prompt(prompt)
                continue
            raise
    raise ExternalAPIError("Claude review failed after retries")
```

### 23.11 Retry and Partial Completion Rules

| Failure case | Module status | Whole scan status | Behavior |
|---|---|---|---|
| `subfinder` fails, DNS/httpx still run | `partial` | `partial` or `completed` | Continue with reduced discovery |
| Shodan key missing or Shodan 429 | `partial` | `completed` | Skip Shodan enrichment only |
| OSV live API down, cache available | `completed` | `completed` | Use cached data |
| OSV live API down, no cache | `partial` | `partial` | Return findings for packages already resolved |
| Claude timeout with retries exhausted | `partial` | `partial` | Dependency and surface findings still ship |
| Pydantic config invalid | `failed` | `failed` | Abort before scan starts |

### 23.12 Unified Findings JSON Example

```json
[
  {
    "finding_id": "surface:api.example.com:dangling_cname",
    "scan_id": "d7b8a761-8d54-4e95-b954-b941dc6140b2",
    "repo_id": "4f7e69df-5410-4693-b2dc-8730672d0a48",
    "module": "attack_surface",
    "kind": "surface",
    "title": "Dangling Cname on api.example.com",
    "severity": "high",
    "confidence": "high",
    "summary": "CNAME points to an unclaimed Netlify target.",
    "evidence": { "cname": "old-site.netlify.app", "provider": "netlify" },
    "location": { "host": "api.example.com", "ip": null, "ports": [443] },
    "asset": { "host": "api.example.com", "status": "dangling", "technologies": ["Cloudflare"] },
    "remediation": { "action": "remove_or_reclaim_dns_target" },
    "source_refs": ["subfinder"],
    "tags": ["attack-surface", "dangling_cname"],
    "raw": {},
    "created_at": "2026-04-15T18:22:11Z"
  }
]
```

---

## 24. Configuration Architecture

Sentinel uses explicit dependency injection so modules are testable, hosted workers and local CLI share the same code paths, and external clients can be swapped without changing module logic.

### 24.1 Configuration Sources and Precedence

Configuration precedence, highest first:

1. CLI flags
2. Environment variables
3. `sentinel.yml`
4. Built-in defaults

Rules: secrets must not be stored in `sentinel.yml`; it declares behavior, thresholds, enabled stages, and provider selection only. API keys are resolved at runtime from environment.

### 24.2 `sentinel.yml` to Runtime Object Mapping

```yaml
# sentinel.yml example
scan:
  modules: [attack_surface, dep_risk, code_security]
  max_concurrency: 4
  fail_open_on_module_error: true

attack_surface:
  enabled: true
  domain_seeds: [example.com]
  tools:
    use_amass_if_available: false
    shodan_enabled: true
  timeouts:
    subfinder_seconds: 45
    httpx_seconds: 30

deps:
  enabled: true
  ecosystems: [PyPI, npm]
  osv:
    use_live_query_on_cache_miss: true
    cache_ttl_hours: 24

llm:
  provider: anthropic
  model: claude-sonnet-4-6
  code_security:
    enabled: true
    categories: [access_control, injection, secrets, ssrf, deserialization, crypto_tls]
    max_tokens_per_review: 6000

dashboard:
  enabled: true
  host: 127.0.0.1
  port: 4000
  auto_open: true
```

Mapped into runtime Pydantic config:

```python
from pathlib import Path
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from typing import Literal


class ScanConfig(BaseModel):
    modules: list[ModuleName] = Field(default_factory=lambda: ["attack_surface", "dep_risk", "code_security"])
    max_concurrency: int = 4
    fail_open_on_module_error: bool = True


class AttackSurfaceToolsConfig(BaseModel):
    use_amass_if_available: bool = False
    shodan_enabled: bool = True


class AttackSurfaceTimeoutsConfig(BaseModel):
    subfinder_seconds: int = 45
    httpx_seconds: int = 30


class AttackSurfaceConfig(BaseModel):
    enabled: bool = True
    domain_seeds: list[str] = Field(default_factory=list)
    tools: AttackSurfaceToolsConfig = Field(default_factory=AttackSurfaceToolsConfig)
    timeouts: AttackSurfaceTimeoutsConfig = Field(default_factory=AttackSurfaceTimeoutsConfig)


class OSVConfig(BaseModel):
    use_live_query_on_cache_miss: bool = True
    cache_ttl_hours: int = 24


class DependencyConfig(BaseModel):
    enabled: bool = True
    ecosystems: list[Literal["PyPI", "npm"]] = Field(default_factory=lambda: ["PyPI", "npm"])
    osv: OSVConfig = Field(default_factory=OSVConfig)


class CodeSecurityConfig(BaseModel):
    enabled: bool = True
    categories: list[str] = Field(default_factory=lambda: [
        "access_control", "injection", "secrets", "ssrf", "deserialization", "crypto_tls",
    ])
    max_tokens_per_review: int = 6000


class LLMConfig(BaseModel):
    provider: Literal["anthropic", "openai"] = "anthropic"
    model: str = "claude-sonnet-4-6"
    code_security: CodeSecurityConfig = Field(default_factory=CodeSecurityConfig)


class DashboardConfig(BaseModel):
    enabled: bool = True
    host: str = "127.0.0.1"
    port: int = 4000
    auto_open: bool = True


class RuntimeSecrets(BaseModel):
    github_app_id: str | None = None
    github_app_private_key: SecretStr | None = None
    github_webhook_secret: SecretStr | None = None
    github_token: SecretStr | None = None
    shodan_api_key: SecretStr | None = None
    anthropic_api_key: SecretStr | None = None
    openai_api_key: SecretStr | None = None
    database_url: SecretStr | None = None
    redis_url: SecretStr | None = None


class SentinelConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scan: ScanConfig = Field(default_factory=ScanConfig)
    attack_surface: AttackSurfaceConfig = Field(default_factory=AttackSurfaceConfig)
    deps: DependencyConfig = Field(default_factory=DependencyConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    dashboard: DashboardConfig = Field(default_factory=DashboardConfig)
    secrets: RuntimeSecrets = Field(default_factory=RuntimeSecrets)
    project_root: Path = Path(".")
```

### 24.3 Config Loader

```python
import os
import yaml


def load_yaml_config(path: Path) -> dict:
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def load_runtime_config(
    config_path: Path,
    env: dict[str, str] | None = None,
    overrides: dict[str, object] | None = None,
) -> SentinelConfig:
    env = env or os.environ
    base = load_yaml_config(config_path)

    config = SentinelConfig.model_validate({
        **base,
        **(overrides or {}),
        "secrets": {
            "github_app_id": env.get("GITHUB_APP_ID"),
            "github_app_private_key": env.get("GITHUB_APP_PRIVATE_KEY"),
            "github_webhook_secret": env.get("GITHUB_WEBHOOK_SECRET"),
            "github_token": env.get("GITHUB_TOKEN"),
            "shodan_api_key": env.get("SHODAN_API_KEY"),
            "anthropic_api_key": env.get("ANTHROPIC_API_KEY"),
            "openai_api_key": env.get("OPENAI_API_KEY"),
            "database_url": env.get("DATABASE_URL"),
            "redis_url": env.get("REDIS_URL"),
        },
        "project_root": str(config_path.parent),
    })

    validate_runtime_requirements(config)
    return config
```

### 24.4 Validation Rules

```python
def validate_runtime_requirements(config: SentinelConfig) -> None:
    if config.llm.code_security.enabled:
        if config.llm.provider == "anthropic" and not config.secrets.anthropic_api_key:
            raise ConfigError("llm.provider=anthropic requires ANTHROPIC_API_KEY")
        if config.llm.provider == "openai" and not config.secrets.openai_api_key:
            raise ConfigError("llm.provider=openai requires OPENAI_API_KEY")
    # Missing SHODAN_API_KEY degrades functionality but is not fatal — module runs with reduced discovery
```

### 24.5 Service Container / DI Wiring

```python
from dataclasses import dataclass


@dataclass(slots=True)
class ServiceContainer:
    config: SentinelConfig
    redis: Any
    db: Any
    github: Any
    shodan: Any | None
    osv: Any
    llm: Any | None
    attack_surface: AttackSurfaceModule
    dep_risk: DependencyRiskModule
    code_security: CodeSecurityModule


def build_container(config: SentinelConfig) -> ServiceContainer:
    redis_client = build_redis_client(config.secrets.redis_url)
    db_client = build_db_client(config.secrets.database_url)
    github_client = build_github_client(config.secrets)
    shodan_client = (
        build_shodan_client(config.secrets.shodan_api_key)
        if config.attack_surface.tools.shodan_enabled else None
    )
    osv_client = build_osv_client(redis_client, db_client, config.deps.osv)
    llm_client = build_llm_client(config.llm, config.secrets)

    return ServiceContainer(
        config=config,
        redis=redis_client,
        db=db_client,
        github=github_client,
        shodan=shodan_client,
        osv=osv_client,
        llm=llm_client,
        attack_surface=AttackSurfaceService(config, shodan_client),
        dep_risk=DependencyRiskService(config, osv_client),
        code_security=CodeSecurityService(config, llm_client),
    )
```

### 24.6 API Key Resolution at Runtime

Modules must not read `os.environ` directly. They receive already-resolved clients through DI.

```python
def build_llm_client(config: LLMConfig, secrets: RuntimeSecrets) -> Any:
    if config.provider == "anthropic":
        if not secrets.anthropic_api_key:
            return None
        return AnthropicClient(
            api_key=secrets.anthropic_api_key.get_secret_value(),
            model=config.model,
        )
    if config.provider == "openai":
        if not secrets.openai_api_key:
            return None
        return OpenAIClient(
            api_key=secrets.openai_api_key.get_secret_value(),
            model=config.model,
        )
    raise ConfigError(f"Unsupported llm.provider={config.provider}")
```

### 24.7 Plugin Architecture for Ecosystem Parsers

New ecosystem parsers register via a simple protocol. v1 ships PyPI + npm; v2 adds Go/Rust.

```python
from typing import Protocol

class EcosystemParser(Protocol):
    ecosystem: str                     # "pypi" | "npm" | "go" | "rust"
    manifest_patterns: list[str]       # e.g. ["requirements*.txt", "Pipfile.lock"]

    def parse(self, manifest_path: str) -> list[PackageRef]: ...
    def build_dep_graph(self, manifest_path: str) -> "DepGraph": ...

ECOSYSTEM_PARSERS: dict[str, EcosystemParser] = {}

def register_parser(parser: EcosystemParser) -> None:
    ECOSYSTEM_PARSERS[parser.ecosystem] = parser

# Auto-registered at import
register_parser(PyPIParser())
register_parser(NpmParser())
```

### 24.8 Testability via Injection

```python
def test_code_security_handles_llm_timeout() -> None:
    config = SentinelConfig()
    fake_llm = FakeLLMClient(error=TimeoutError("upstream timeout"))
    service = CodeSecurityService(config, fake_llm)

    result = service.run(make_scan_context_with_pr())

    assert result.status == "partial"
    assert result.findings == []
    assert result.errors[0].provider == "anthropic"
```

---

## 25. Dashboard Technical Spec

The dashboard is a Next.js 16 App Router application that renders scan history, live progress, and normalized findings from the `UnifiedFinding` stream.

### 25.1 App Router File Structure

```
dashboard/
├── app/
│   ├── layout.tsx
│   ├── page.tsx
│   ├── dashboard/
│   │   └── page.tsx
│   ├── repos/
│   │   └── [owner]/
│   │       └── [name]/
│   │           ├── page.tsx
│   │           ├── surface/
│   │           │   └── page.tsx
│   │           ├── deps/
│   │           │   └── page.tsx
│   │           ├── code-security/
│   │           │   └── page.tsx
│   │           └── scans/
│   │               └── [scanId]/
│   │                   └── page.tsx
│   ├── api/
│   │   └── repos/
│   │       ├── route.ts
│   │       └── [repoId]/
│   │           ├── route.ts
│   │           ├── scan/
│   │           │   └── route.ts
│   │           ├── findings/
│   │           │   └── route.ts
│   │           └── scans/
│   │               ├── route.ts
│   │               └── [scanId]/
│   │                   └── route.ts
│   ├── globals.css
│   └── providers.tsx
├── components/
│   ├── findings-table.tsx
│   ├── live-scan-status.tsx
│   ├── risk-score-badge.tsx
│   └── repo-header.tsx
├── lib/
│   ├── api.ts
│   ├── findings.ts
│   ├── websocket.ts
│   └── types.ts
└── middleware.ts
```

### 25.2 Dashboard Data Types

The frontend consumes normalized findings, not module-native payloads.

```typescript
// lib/types.ts
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type ModuleName = "attack_surface" | "dep_risk" | "code_security";
export type FindingKind = "surface" | "dependency" | "code";

export interface UnifiedFinding {
  finding_id: string;
  scan_id: string;
  repo_id: string;
  module: ModuleName;
  kind: FindingKind;
  title: string;
  severity: Severity;
  confidence: "high" | "medium" | "low";
  summary: string;
  evidence: Record<string, unknown>;
  location: {
    file?: string;
    line?: number;
    route?: string | null;
    method?: string | null;
    host?: string;
    ip?: string | null;
    ports?: number[];
    package?: string;
    manifest?: string | null;
  };
  asset: Record<string, unknown>;
  remediation: Record<string, unknown>;
  source_refs: string[];
  tags: string[];
  raw: Record<string, unknown>;
  created_at: string;
}
```

### 25.3 Scan and Progress Schemas

```typescript
export interface ScanSummary {
  id: string;
  repo_id: string;
  scan_type: "full" | "attack_surface" | "dep_risk" | "code_security";
  trigger: "push" | "pr" | "scheduled" | "manual" | "cli";
  status: "pending" | "running" | "completed" | "partial" | "failed";
  commit_sha?: string | null;
  pr_number?: number | null;
  started_at?: string | null;
  completed_at?: string | null;
  error?: string | null;
}

export interface ProgressEvent {
  type: "progress";
  module: ModuleName;
  step: string;
  pct: number;
  message?: string;
}

export interface FindingEvent {
  type: "finding";
  finding: UnifiedFinding;
}

export interface ModuleErrorEvent {
  type: "module_error";
  module: ModuleName;
  stage: string;
  provider?: string;
  retryable: boolean;
  message: string;
}

export interface CompleteEvent {
  type: "complete";
  summary: {
    status: "completed" | "partial" | "failed";
    finding_count: number;
    module_statuses: Record<ModuleName, string>;
  };
}

export type ScanStreamEvent =
  | ProgressEvent
  | FindingEvent
  | ModuleErrorEvent
  | CompleteEvent;
```

### 25.4 API Routes and Payloads

#### `GET /api/repos`
Response: `[{ id, owner, name, default_branch, risk_score, last_scanned_at }]`

#### `GET /api/repos/[repoId]`
Response: `{ id, owner, name, default_branch, risk_score, stats: { surface, dependency, code } }`

#### `POST /api/repos/[repoId]/scan`
Request: `{ "modules": ["attack_surface", "dep_risk", "code_security"], "domain_seeds": ["example.com"] }`
Response: `{ "scan_id": "...", "status": "pending" }`

#### `GET /api/repos/[repoId]/findings`
Query: `module`, `severity`, `kind`, `pr`, `reachable`, `page`, `page_size`
Response: `{ "items": [...], "total": 12, "page": 1, "page_size": 25 }`

#### `GET /api/repos/[repoId]/scans/[scanId]`
Response: `{ "scan": { id, status }, "module_statuses": { attack_surface, dep_risk, code_security }, "findings_preview": [] }`

### 25.5 App Router Handlers

```typescript
// app/api/repos/[repoId]/findings/route.ts
import { NextRequest, NextResponse } from "next/server";
import { backendFetch } from "@/lib/api";

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ repoId: string }> },
) {
  const { repoId } = await params;
  const query = request.nextUrl.searchParams.toString();
  const res = await backendFetch(`/api/v1/repos/${repoId}/findings?${query}`);
  return NextResponse.json(await res.json(), { status: res.status });
}
```

```typescript
// app/api/repos/[repoId]/scan/route.ts
import { NextRequest, NextResponse } from "next/server";
import { backendFetch } from "@/lib/api";

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ repoId: string }> },
) {
  const { repoId } = await params;
  const body = await request.json();
  const res = await backendFetch(`/api/v1/repos/${repoId}/scan`, {
    method: "POST",
    body: JSON.stringify(body),
  });
  return NextResponse.json(await res.json(), { status: res.status });
}
```

### 25.6 Findings JSON Schema (for static dashboard / local mode)

```typescript
export const UnifiedFindingSchema = {
  type: "object",
  required: ["finding_id", "scan_id", "repo_id", "module", "kind", "title",
             "severity", "confidence", "summary", "evidence", "location",
             "asset", "remediation", "source_refs", "tags", "raw", "created_at"],
  properties: {
    finding_id: { type: "string" },
    scan_id: { type: "string", format: "uuid" },
    repo_id: { type: "string", format: "uuid" },
    module: { enum: ["attack_surface", "dep_risk", "code_security"] },
    kind: { enum: ["surface", "dependency", "code"] },
    title: { type: "string" },
    severity: { enum: ["critical", "high", "medium", "low", "info"] },
    confidence: { enum: ["high", "medium", "low"] },
    summary: { type: "string" },
    evidence: { type: "object", additionalProperties: true },
    location: { type: "object", additionalProperties: true },
    asset: { type: "object", additionalProperties: true },
    remediation: { type: "object", additionalProperties: true },
    source_refs: { type: "array", items: { type: "string" } },
    tags: { type: "array", items: { type: "string" } },
    raw: { type: "object", additionalProperties: true },
    created_at: { type: "string", format: "date-time" },
  },
} as const;
```

### 25.7 WebSocket Client for Live Scan Progress

```typescript
// lib/websocket.ts
import type { ScanStreamEvent, UnifiedFinding } from "@/lib/types";

export interface ScanStreamHandlers {
  onProgress?: (event: ScanStreamEvent) => void;
  onFinding?: (finding: UnifiedFinding) => void;
  onError?: (message: string) => void;
  onComplete?: (event: ScanStreamEvent) => void;
}

export function connectScanStream(
  scanId: string,
  handlers: ScanStreamHandlers,
): () => void {
  const protocol = window.location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${protocol}://${window.location.host}/ws/scans/${scanId}`);

  ws.onmessage = (message) => {
    const event = JSON.parse(message.data) as ScanStreamEvent;
    if (event.type === "progress" || event.type === "module_error") {
      handlers.onProgress?.(event);
    }
    if (event.type === "finding") {
      handlers.onFinding?.(event.finding);
    }
    if (event.type === "complete") {
      handlers.onComplete?.(event);
      ws.close();
    }
  };

  ws.onerror = () => handlers.onError?.("Live scan connection failed");

  return () => ws.close();
}
```

### 25.8 React Live Scan Component

```tsx
// components/live-scan-status.tsx
"use client";
import { useEffect, useState } from "react";
import { connectScanStream } from "@/lib/websocket";
import type { ScanStreamEvent, UnifiedFinding } from "@/lib/types";

export function LiveScanStatus({ scanId }: { scanId: string }) {
  const [events, setEvents] = useState<ScanStreamEvent[]>([]);
  const [findings, setFindings] = useState<UnifiedFinding[]>([]);

  useEffect(() => {
    return connectScanStream(scanId, {
      onProgress: (event) => setEvents((current) => [...current, event]),
      onFinding: (finding) => setFindings((current) => [finding, ...current]),
      onError: (message) =>
        setEvents((current) => [
          ...current,
          { type: "module_error", module: "code_security", stage: "websocket", retryable: true, message },
        ]),
    });
  }, [scanId]);

  return (
    <section>
      <p>{events.at(-1)?.type === "progress" ? (events.at(-1) as any).step : "Waiting for updates"}</p>
      <ul>
        {findings.map((finding) => (
          <li key={finding.finding_id}>
            <strong>{finding.severity.toUpperCase()}</strong> {finding.title}
          </li>
        ))}
      </ul>
    </section>
  );
}
```

### 25.9 Server-Side Page Example

```tsx
// app/repos/[owner]/[name]/page.tsx
import { backendFetch } from "@/lib/api";
import type { UnifiedFinding } from "@/lib/types";

export default async function RepoPage({
  params,
}: {
  params: Promise<{ owner: string; name: string }>;
}) {
  const { owner, name } = await params;
  const repoRes = await backendFetch(`/api/v1/repos/by-slug/${owner}/${name}`);
  const repo = await repoRes.json();
  const findingsRes = await backendFetch(`/api/v1/repos/${repo.id}/findings?page=1&page_size=10`);
  const findings: { items: UnifiedFinding[] } = await findingsRes.json();

  return (
    <main>
      <h1>{owner}/{name}</h1>
      <p>Risk score: {repo.risk_score}</p>
      <p>Open findings: {findings.items.length}</p>
    </main>
  );
}
```

### 25.10 UI Rendering Rules

- Always render from `UnifiedFinding`, never from raw module-native payloads.
- Severity color and ordering must be consistent across all tabs.
- Attack surface views: emphasize `location.host`, `location.ports`, and `tags`.
- Dependency views: emphasize `asset.package`, `evidence.risk_score`, and `remediation.fix_version`.
- Code security views: emphasize `location.file`, `location.line`, `evidence.route`, and `remediation.suggestion`.
- Live scan pages: append findings as they arrive; preserve event order for auditability.

### 25.11 Risk Score Badge Component

```tsx
// components/risk-score-badge.tsx
const SCORE_COLORS = {
  critical: "bg-red-600 text-white",     // 80–100
  high: "bg-orange-500 text-white",      // 60–79
  medium: "bg-yellow-400 text-black",    // 40–59
  low: "bg-green-500 text-white",        // 0–39
} as const;

export function RiskScore({ score }: { score: number }) {
  const level =
    score >= 80 ? "critical" : score >= 60 ? "high" : score >= 40 ? "medium" : "low";
  return (
    <span className={`px-3 py-1 rounded-full font-mono font-bold text-lg ${SCORE_COLORS[level]}`}>
      {Math.round(score)}
    </span>
  );
}
```

### 25.12 Local Dashboard Mode

For CLI-driven reports, the dashboard consumes a static `findings.json` with the same `UnifiedFinding[]` schema. Local mode and hosted mode are identical at the component layer.

```python
# sentinel/dashboard_server.py
import subprocess, sys, webbrowser
from pathlib import Path

def start_local_dashboard(report_dir: str, port: int = 4000, auto_open: bool = True) -> subprocess.Popen:
    """
    Starts the Next.js static dashboard as a background subprocess after `sentinel scan` completes.
    The dashboard reads findings from report_dir via /api/findings?path=...
    """
    dashboard_dist = Path(__file__).parent.parent / "dashboard" / ".next"
    if not dashboard_dist.exists():
        return _start_json_viewer(report_dir, port, auto_open)  # minimal fallback

    proc = subprocess.Popen(
        [sys.executable, "-m", "sentinel._dashboard_runner"],
        env={"PORT": str(port), "SENTINEL_REPORT_DIR": report_dir, "NEXT_TELEMETRY_DISABLED": "1"},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    print(f"\n  Dashboard: http://localhost:{port}\n")
    if auto_open:
        webbrowser.open(f"http://localhost:{port}")
    return proc

---

## 26. LLM Prompt Engineering Reference

### 26.1 Code Security Review — Production System Prompt

This is the exact system prompt sent for every PR review. It is framework-parameterized (see §26.3 for per-framework variants).

```
You are a security engineer reviewing a pull request diff for security vulnerabilities.
Your task is to identify real, exploitable security issues — not style or best-practice suggestions.

You will receive:
1. A list of new or changed routes and their detected middleware signals
2. Excerpts of existing correctly-protected routes (as few-shot examples of safe patterns)
3. The diff hunks for changed files
4. Pre-analysis hits from a deterministic scanner (high-entropy strings, known-bad patterns)

Return ONLY a JSON array. Each element must have exactly these fields:
  - "category": one of "access_control" | "injection" | "secrets" | "ssrf" | "deserialization" | "crypto_tls" | "other"
  - "issue_type": a short snake_case slug (e.g. "missing_auth", "idor", "sql_injection", "secret_in_diff", "unsafe_pickle", "insecure_skip_verify")
  - "route": the HTTP route pattern if applicable, else null
  - "method": the HTTP method if applicable, else null
  - "file": the file path (relative to repo root)
  - "line": the line number in the file, or null if not pinpointable
  - "severity": one of "critical" | "high" | "medium" | "low"
  - "cwe_id": an integer CWE number if you can map it confidently, else null
  - "explanation": 1-3 sentences explaining the issue and why it is exploitable
  - "fix_suggestion": 1-2 sentences describing the minimal correct fix

Return [] if you find no issues.

IMPORTANT RULES:
- DO NOT flag patterns that clearly match the established safe usage shown in the few-shot examples.
- DO NOT flag informational or theoretical issues — only flag issues a competent attacker could realistically exploit.
- DO NOT emit chain-of-thought reasoning, commentary, or any text outside the JSON array.
- If you are unsure whether something is a real vulnerability, do NOT flag it.
- Secrets: only flag credentials that appear to be real (high entropy, matching known key formats). Ignore example/placeholder values.
```

### 26.2 Prompt Template with Placeholders

```python
SYSTEM_PROMPT = """\
You are a security engineer reviewing a pull request diff for security vulnerabilities.
... (see §26.1 above) ...
"""

USER_PROMPT_TEMPLATE = """\
## Framework
{framework}

## New/changed routes detected in this diff
{routes_block}

## Existing correctly-protected routes (safe pattern examples)
{safe_examples_block}

## Diff hunks
{diff_block}

## Pre-analysis hits (deterministic scanner)
{prepass_block}

---
Return a JSON array of security findings. Return [] if none.
"""

def build_user_prompt(pack: ContextPack) -> str:
    routes_block = "\n".join(
        f"- {r.method or 'ANY'} {r.route or '(handler)'} in {r.file}"
        f"  auth_signals: {r.auth_signals or 'none'}"
        f"  sink_signals: {r.sink_signals or 'none'}"
        for r in pack.routes
    ) or "(no new routes detected)"

    safe_examples_block = "\n\n".join(pack.safe_pattern_examples) or "(no examples available)"

    diff_block = "\n\n".join(
        f"### {h.file}\n```diff\n{h.patch}\n```"
        for h in pack.diff_hunks
    )

    prepass_block = "\n".join(
        f"- {hit.type} at {hit.file}:{hit.line}: {hit.detail}"
        for hit in pack.prepass_hits
    ) or "(none)"

    return USER_PROMPT_TEMPLATE.format(
        framework=pack.framework or "unknown",
        routes_block=routes_block,
        safe_examples_block=safe_examples_block,
        diff_block=diff_block,
        prepass_block=prepass_block,
    )
```

### 26.3 Per-Framework Prompt Adjustments

The system prompt is identical across frameworks. The user prompt's `routes_block` and `safe_examples_block` use framework-appropriate terminology:

| Framework | Route pattern example | Auth signal vocabulary | Safe example shape |
|-----------|----------------------|----------------------|--------------------|
| **FastAPI** | `GET /api/users/{id}` | `Depends(get_current_user)`, `Security(...)` | `@router.get("/admin", dependencies=[Depends(require_admin)])` |
| **Flask** | `GET /api/users/<id>` | `@login_required`, `@jwt_required()` | `@app.route("/admin")\n@login_required\ndef admin(): ...` |
| **Django** | `GET /api/users/<id>/` | `@login_required`, `IsAuthenticated`, `permission_classes` | `class AdminView(APIView):\n    permission_classes = [IsAuthenticated, IsAdminUser]` |
| **Express** | `GET /api/users/:id` | `authenticate`, `requireAuth`, middleware position | `router.get('/admin', authenticate, requireAdmin, handler)` |
| **Next.js API** | `GET /api/users/[id]` | `getServerSession`, `withAuth`, middleware export | `export { default } from 'next-auth/middleware'\nexport const config = { matcher: ['/admin/:path*'] }` |

Framework is detected at scan time via `detect_framework(repo_path)` (§23.7) and injected into the prompt pack.

### 26.4 Few-Shot Examples Format

Two examples are injected into `safe_examples_block` — one "correctly protected" route from the repo itself, and one generic safe pattern for the detected framework:

```python
SAFE_PATTERN_FASTAPI = """\
# Safe example — FastAPI with explicit auth dependency:
@router.get("/users/{user_id}/profile")
async def get_user_profile(
    user_id: int,
    current_user: User = Depends(get_current_user),  # ← auth enforced
    db: Session = Depends(get_db),
):
    if current_user.id != user_id and not current_user.is_admin:
        raise HTTPException(status_code=403)
    return db.query(User).get(user_id)
"""

SAFE_PATTERN_EXPRESS = """\
// Safe example — Express with middleware guard:
router.get('/users/:id/profile',
  authenticate,        // ← verifies JWT, sets req.user
  requireSelf,         // ← checks req.user.id === req.params.id
  async (req, res) => {
    const user = await User.findById(req.params.id);
    res.json(user);
  }
);
"""
```

### 26.5 CWE Mapping in the Prompt

The prompt asks the model to map confidently to a CWE integer when it can. The model is not given the full CWE list — it maps from its training knowledge. Post-processing validates the CWE is in a known-valid set:

```python
VALID_CWES_BY_CATEGORY = {
    "access_control": {284, 285, 639, 862, 863, 306, 732},
    "injection":      {89, 78, 77, 94, 1336, 74, 943},
    "secrets":        {798, 259, 321},
    "ssrf":           {918},
    "deserialization":{502},
    "crypto_tls":     {326, 327, 328, 330, 338, 347, 295},
    "other":          set(),   # any CWE accepted
}

def validate_cwe(category: str, cwe_id: Optional[int]) -> Optional[int]:
    if cwe_id is None:
        return None
    valid = VALID_CWES_BY_CATEGORY.get(category, set())
    if valid and cwe_id not in valid:
        return None   # reject implausible mapping; don't store garbage
    return cwe_id
```

### 26.6 Chunking Strategy for Large Diffs

When `token_estimate > MAX_TOKENS_PER_PR_REVIEW` (6000), diff hunks are chunked by file with this priority order:

```python
FILE_PRIORITY_RULES = [
    # Highest priority — new/changed route definitions
    lambda f: any(sig in f for sig in ["router.", "@app.route", "router.get", "router.post", "app.get"]),
    # High priority — auth/middleware files
    lambda f: any(kw in f.lower() for kw in ["auth", "middleware", "guard", "permission", "require"]),
    # Medium — model/schema files that define trust boundaries
    lambda f: any(kw in f.lower() for kw in ["model", "schema", "serializer"]),
    # Low — test files (deprioritized, rarely contain exploitable code)
    lambda f: "test" in f.lower() or "spec" in f.lower(),
]

def prioritized_hunks(diff: ParsedDiff, routes: List[RouteContext], budget: int) -> List[DiffHunk]:
    route_files = {r.file for r in routes}
    
    def priority(hunk: DiffHunk) -> int:
        if hunk.file in route_files:
            return 0
        for i, rule in enumerate(FILE_PRIORITY_RULES):
            if rule(hunk.file):
                return i + 1
        return len(FILE_PRIORITY_RULES) + 1

    sorted_hunks = sorted(diff.hunks, key=priority)
    
    selected, token_count = [], 0
    for hunk in sorted_hunks:
        hunk_tokens = estimate_tokens(hunk.patch)
        if token_count + hunk_tokens > budget:
            break
        selected.append(hunk)
        token_count += hunk_tokens
    
    return selected
```

---

## 27. CLI Implementation Reference

### 27.1 Full Click Command Tree

```python
# sentinel/cli.py
import click
from rich.console import Console

console = Console()

@click.group()
@click.version_option()
def cli():
    """Sentinel — attack surface, dependency risk, and LLM code security in one pipeline."""
    pass


@cli.command()
@click.option("--repo", required=True, help="GitHub repo URL or owner/name")
@click.option("--domain", default=None, help="Optional seed domain for attack-surface enumeration")
@click.option("--stages", default="all",
              help="Comma-separated: surface,deps,code or 'all'")
@click.option("--config", default="sentinel.yml", show_default=True,
              help="Path to sentinel.yml config file")
@click.option("--output", default="./sentinel-report", show_default=True,
              help="Directory to write findings artifacts")
@click.option("--format", "output_format", default="json",
              type=click.Choice(["json", "html", "markdown"]), show_default=True)
@click.option("--fail-on", default="high",
              type=click.Choice(["critical", "high", "medium", "low", "none"]),
              show_default=True, help="Exit code 1 if findings at this severity or above")
@click.option("--quiet", "-q", is_flag=True, default=False,
              help="No Rich output, no auto-dashboard. Artifacts and exit codes only.")
@click.option("--no-dashboard", is_flag=True, default=False,
              help="Full CLI output but skip auto-starting dashboard after scan.")
@click.option("--commit", default=None, help="Pin to specific commit SHA (for E2E tests)")
def scan(repo, domain, stages, config, output, output_format, fail_on, quiet, no_dashboard, commit):
    """Run a full scan (all stages by default) against a GitHub repo."""
    from sentinel.commands.scan import run_scan_command
    run_scan_command(locals())


@cli.command()
@click.option("--base", default="main", show_default=True, help="Base branch or SHA")
@click.option("--head", default="HEAD", show_default=True, help="Head branch or SHA")
@click.option("--repo", required=True, help="GitHub repo URL")
@click.option("--fail-on", default="high",
              type=click.Choice(["critical", "high", "medium", "low", "none"]))
@click.option("--quiet", "-q", is_flag=True, default=False)
@click.option("--output", default="./sentinel-report")
def diff(base, head, repo, fail_on, quiet, output):
    """Scan only the changed files between two refs. Faster for CI."""
    from sentinel.commands.diff import run_diff_command
    run_diff_command(locals())


@cli.command()
@click.option("--report", default="./sentinel-report", show_default=True,
              help="Path to findings directory or JSON file")
@click.option("--port", default=4000, show_default=True, type=int)
@click.option("--open/--no-open", default=True, show_default=True,
              help="Auto-open browser")
def dashboard(report, port, open):
    """Launch the local web dashboard for a previous scan report."""
    from sentinel.commands.dashboard import run_dashboard_command
    run_dashboard_command(report, port, open)


@cli.command()
@click.option("--input", "input_path", default="./sentinel-report/findings.json")
@click.option("--format", "output_format",
              type=click.Choice(["html", "markdown", "sarif"]), default="html")
@click.option("--output", default="./report.html")
def report(input_path, output_format, output):
    """Convert a findings JSON file to a different format without re-scanning."""
    from sentinel.commands.report import run_report_command
    run_report_command(input_path, output_format, output)


@cli.group()
def auth():
    """Authenticate with GitHub for private repo access."""
    pass


@auth.command("login")
def auth_login():
    """Open browser → GitHub OAuth → save token."""
    from sentinel.commands.auth import run_auth_login
    run_auth_login()


@auth.command("status")
def auth_status():
    """Show current authentication status."""
    from sentinel.commands.auth import run_auth_status
    run_auth_status()


@cli.command()
@click.option("--repo", required=True)
@click.option("--pr", required=True, type=int, help="PR number to review")
@click.option("--quiet", "-q", is_flag=True, default=False)
@click.option("--output", default="./sentinel-report")
def pr(repo, pr, quiet, output):
    """Run code security review on a specific PR without running other stages."""
    from sentinel.commands.pr import run_pr_command
    run_pr_command(repo, pr, quiet, output)


@cli.command()
@click.option("--repo", required=True)
def demo(repo):
    """Run with pre-baked results for conference demos (no live scan)."""
    from sentinel.commands.demo import run_demo_command
    run_demo_command(repo)
```

### 27.2 Rich Progress Structure

```python
# sentinel/display.py
from rich.console import Console
from rich.progress import (
    Progress, SpinnerColumn, BarColumn, TextColumn,
    TimeElapsedColumn, TaskProgressColumn, MofNCompleteColumn,
)
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

console = Console()

STAGE_LABELS = {
    "surface":       "[cyan]Attack Surface[/cyan]",
    "deps":          "[yellow]Dependency Risk[/yellow]",
    "code_security": "[magenta]Code Security[/magenta]",
}

def make_scan_progress() -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn("[bold]{task.description}"),
        BarColumn(bar_width=30),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,   # keep completed rows visible
    )

def render_surface_finding(f: UnifiedFinding) -> Table:
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    t.add_column("key", style="dim", width=18)
    t.add_column("val")
    t.add_row("host",     f.location.get("host", ""))
    t.add_row("status",   f.asset.get("status", ""))
    t.add_row("issue",    f.title)
    t.add_row("severity", _severity_markup(f.severity))
    t.add_row("detail",   f.summary[:120])
    return Panel(t, title=f"[bold]Surface[/bold]", border_style=_severity_color(f.severity))

def render_dep_finding(f: UnifiedFinding) -> Table:
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    t.add_column("key", style="dim", width=18)
    t.add_column("val")
    t.add_row("package",    f.asset.get("package", ""))
    t.add_row("version",    f.asset.get("version", ""))
    t.add_row("risk_score", f"{f.evidence.get('risk_score', 0):.1f}/10")
    t.add_row("reachable",  "yes" if f.confidence == "high" else "no")
    t.add_row("trace",      (f.evidence.get("reachability_trace") or "")[:80])
    t.add_row("severity",   _severity_markup(f.severity))
    t.add_row("fix",        f.remediation.get("fix_version") or "none available")
    return Panel(t, title=f"[bold]Dependency[/bold]", border_style=_severity_color(f.severity))

def render_code_finding(f: UnifiedFinding) -> Table:
    loc = f.location
    cwe = f.evidence.get("cwe_id")
    t = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    t.add_column("key", style="dim", width=18)
    t.add_column("val")
    t.add_row("location",   f"{loc.get('file', '')}:{loc.get('line', '')}")
    t.add_row("route",      loc.get("route") or "—")
    t.add_row("category",   f.tags[1] if len(f.tags) > 1 else "—")
    t.add_row("issue_type", f.tags[2] if len(f.tags) > 2 else "—")
    t.add_row("severity",   _severity_markup(f.severity))
    t.add_row("cwe",        f"CWE-{cwe}" if cwe else "—")
    t.add_row("summary",    f.summary[:200])
    t.add_row("fix",        (f.remediation.get("suggestion") or "")[:120])
    return Panel(t, title=f"[bold]Code Security[/bold]", border_style=_severity_color(f.severity))

def _severity_color(severity: str) -> str:
    return {"critical": "red", "high": "orange3", "medium": "yellow", "low": "green", "info": "blue"}.get(severity, "white")

def _severity_markup(severity: str) -> str:
    color = _severity_color(severity)
    return f"[{color}]{severity.upper()}[/{color}]"
```

### 27.3 Findings Summary Table (Post-Scan)

```python
def render_summary_table(findings: List[UnifiedFinding], elapsed_sec: float) -> None:
    from rich.table import Table
    from rich import box

    by_stage: dict[str, list] = {"surface": [], "deps": [], "code_security": []}
    for f in findings:
        by_stage[f.module].append(f)

    t = Table(title="Sentinel Scan Summary", box=box.ROUNDED, show_lines=True)
    t.add_column("Stage", style="bold")
    t.add_column("Critical", style="red", justify="right")
    t.add_column("High", style="orange3", justify="right")
    t.add_column("Medium", style="yellow", justify="right")
    t.add_column("Low", style="green", justify="right")
    t.add_column("Total", justify="right")

    stage_names = {
        "attack_surface": "Attack Surface",
        "dep_risk":       "Dependency Risk",
        "code_security":  "Code Security",
    }
    for module, label in stage_names.items():
        fs = [f for f in findings if f.module == module]
        counts = {s: sum(1 for f in fs if f.severity == s) for s in ("critical", "high", "medium", "low")}
        t.add_row(label, str(counts["critical"]), str(counts["high"]),
                  str(counts["medium"]), str(counts["low"]), str(len(fs)))

    console.print(t)
    console.print(f"\n  [dim]Scan completed in {elapsed_sec:.1f}s[/dim]")
```

### 27.4 Output Behavior Matrix

| Mode | `stdout` | Dashboard | Artifacts | Exit code |
|------|----------|-----------|-----------|-----------|
| **Default** | Rich progress + per-finding panels + summary table | Auto-started, browser opens if `auto_open` | Always written to `--output` | 1 if findings ≥ `--fail-on` severity |
| **`--quiet` / `-q`** | Suppressed (errors → stderr only) | Not started | Always written | 1 if findings ≥ `--fail-on` severity |
| **`--no-dashboard`** | Same as default | Not started | Always written | 1 if findings ≥ `--fail-on` severity |

```python
# sentinel/commands/scan.py

def run_scan_command(args: dict) -> None:
    quiet = args["quiet"]
    no_dashboard = args["no_dashboard"]
    
    config = load_runtime_config(Path(args["config"]))
    services = build_container(config)
    
    if not quiet:
        _print_scan_header(args["repo"])
    
    with make_scan_progress() as progress:
        surface_task = progress.add_task(STAGE_LABELS["surface"], total=7)
        deps_task = progress.add_task(STAGE_LABELS["deps"], total=100)
        code_task = progress.add_task(STAGE_LABELS["code_security"], total=4)

        findings = run_scan(ctx, services, progress_callbacks={
            "surface": lambda pct: progress.update(surface_task, completed=pct * 7 / 100),
            "deps": lambda pct: progress.update(deps_task, completed=pct),
            "code": lambda pct: progress.update(code_task, completed=pct * 4 / 100),
        })

    write_artifacts(findings, args["output"], args["output_format"])

    if not quiet:
        render_summary_table(findings, elapsed)
        for f in sorted(findings, key=lambda x: SEVERITY_ORDER[x.severity]):
            if f.module == "attack_surface":
                console.print(render_surface_finding(f))
            elif f.module == "dep_risk":
                console.print(render_dep_finding(f))
            elif f.module == "code_security":
                console.print(render_code_finding(f))

    if not quiet and not no_dashboard and config.dashboard.enabled:
        start_local_dashboard(args["output"], config.dashboard.port, config.dashboard.auto_open)

    _exit_with_severity_check(findings, args["fail_on"])
```

---

## 28. Observability & Performance Targets

### 28.1 Latency SLOs

| Stage | P50 | P95 | P99 | Hard timeout |
|-------|-----|-----|-----|-------------|
| Attack surface (full, with Shodan) | 90s | 180s | 300s | 5 min |
| Attack surface (no Shodan) | 45s | 90s | 150s | 3 min |
| Dependency risk (50 deps, cache hit) | 3s | 8s | 15s | 60s |
| Dependency risk (50 deps, cache miss) | 12s | 30s | 60s | 120s |
| Code security PR review (< 200 lines diff) | 8s | 20s | 35s | 90s |
| End-to-end `sentinel scan` (all stages) | 120s | 240s | 360s | 8 min |

**PR review SLO** (§6 Trigger Model): Code security stage must complete within **60 seconds** of task dequeue for the GitHub Check Run to appear before most humans finish reading the diff.

### 28.2 Metrics to Emit (OpenTelemetry / Prometheus)

All metrics use the prefix `sentinel_`.

```python
# sentinel/metrics.py
from opentelemetry import metrics

meter = metrics.get_meter("sentinel", version="0.3")

# Counters
scans_started         = meter.create_counter("sentinel_scans_started_total",
                            description="Scans enqueued, by trigger and module")
scans_completed       = meter.create_counter("sentinel_scans_completed_total",
                            description="Scans completed, by status (completed|partial|failed)")
findings_emitted      = meter.create_counter("sentinel_findings_emitted_total",
                            description="Findings produced, by module and severity")
llm_requests          = meter.create_counter("sentinel_llm_requests_total",
                            description="LLM API calls, by provider and outcome")
llm_tokens_used       = meter.create_counter("sentinel_llm_tokens_total",
                            description="LLM tokens consumed, by direction (input|output)")
osv_cache_hits        = meter.create_counter("sentinel_osv_cache_hits_total")
osv_cache_misses      = meter.create_counter("sentinel_osv_cache_misses_total")
webhook_received      = meter.create_counter("sentinel_webhooks_received_total",
                            description="GitHub webhooks received, by event type")

# Histograms (record durations in seconds)
scan_duration_s       = meter.create_histogram("sentinel_scan_duration_seconds",
                            description="Wall time per scan stage",
                            unit="s")
llm_latency_s         = meter.create_histogram("sentinel_llm_request_duration_seconds",
                            description="LLM API call latency", unit="s")
osv_query_latency_s   = meter.create_histogram("sentinel_osv_query_duration_seconds",
                            description="OSV API query latency", unit="s")
reachability_duration = meter.create_histogram("sentinel_reachability_duration_seconds",
                            description="tree-sitter reachability check duration", unit="s")

# Gauges
worker_queue_depth    = meter.create_observable_gauge("sentinel_worker_queue_depth",
                            description="Celery queue depths by queue name")
cve_cache_staleness_h = meter.create_observable_gauge("sentinel_cve_cache_staleness_hours",
                            description="Hours since last bulk OSV sync")
```

### 28.3 Metric Labels

| Metric | Labels |
|--------|--------|
| `sentinel_scans_started_total` | `trigger` (push/pr/scheduled/manual/cli), `module` |
| `sentinel_scans_completed_total` | `status` (completed/partial/failed), `module` |
| `sentinel_findings_emitted_total` | `module` (attack_surface/dep_risk/code_security), `severity` |
| `sentinel_llm_requests_total` | `provider` (anthropic/openai), `outcome` (success/rate_limit/timeout/malformed_json) |
| `sentinel_llm_tokens_total` | `direction` (input/output) |
| `sentinel_scan_duration_seconds` | `stage` (surface/deps/code_security/total), `trigger` |

### 28.4 Celery Task Instrumentation

```python
# sentinel/workers/base.py
import time
from functools import wraps
from sentinel.metrics import scan_duration_s, scans_completed, findings_emitted

def instrumented_task(module_name: str):
    """Decorator that wraps a Celery task with timing and metrics."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            start = time.monotonic()
            status = "completed"
            try:
                result = fn(*args, **kwargs)
                for finding in result.findings:
                    findings_emitted.add(1, {
                        "module": module_name,
                        "severity": finding.severity,
                    })
                if result.status in ("partial", "failed"):
                    status = result.status
                return result
            except Exception:
                status = "failed"
                raise
            finally:
                elapsed = time.monotonic() - start
                scan_duration_s.record(elapsed, {"stage": module_name, "trigger": kwargs.get("trigger", "unknown")})
                scans_completed.add(1, {"status": status, "module": module_name})
        return wrapper
    return decorator

# Usage:
@celery_app.task
@instrumented_task("code_security")
def run_pr_review_task(scan_id: str, repo_id: str, pr_number: int, **kwargs):
    ...
```

### 28.5 OpenTelemetry Spans

Critical path spans for a PR review task:

```python
from opentelemetry import trace

tracer = trace.get_tracer("sentinel.code_security")

def run_code_review_with_tracing(ctx: ScanContext, services: ServiceContainer) -> CodeSecurityResult:
    with tracer.start_as_current_span("code_security.review") as root:
        root.set_attribute("repo.id", str(ctx.repo.repo_id))
        root.set_attribute("pr.number", ctx.pr.pr_number if ctx.pr else -1)
        root.set_attribute("trigger", ctx.trigger)

        with tracer.start_as_current_span("code_security.collect_diff"):
            hunks = collect_diff_context(ctx.repo.clone_path, ctx.pr)
            root.set_attribute("diff.hunks", len(hunks))

        with tracer.start_as_current_span("code_security.detect_framework"):
            framework = detect_framework(ctx.repo.clone_path)
            root.set_attribute("framework", framework or "unknown")

        with tracer.start_as_current_span("code_security.extract_routes"):
            routes = extract_route_contexts(ctx.repo.clone_path, hunks)
            root.set_attribute("routes.detected", len(routes))

        with tracer.start_as_current_span("code_security.build_prompt"):
            pack = build_prompt_pack(ctx, hunks, routes)
            root.set_attribute("prompt.tokens_estimated", pack.token_estimate)

        with tracer.start_as_current_span("code_security.llm_review") as llm_span:
            llm_span.set_attribute("llm.provider", services.config.llm.provider)
            llm_span.set_attribute("llm.model", services.config.llm.model)
            findings = review_with_llm(pack)
            llm_span.set_attribute("llm.findings_count", len(findings))

        root.set_attribute("findings.total", len(findings))
        return CodeSecurityResult(status="completed", findings=findings, errors=[], stats={})
```

### 28.6 Slow Scan Detection and Partial Result Handling

Each Celery task has a `soft_time_limit` and a `time_limit`. On `SoftTimeLimitExceeded`, the worker saves partial results before the hard kill:

```python
from celery.exceptions import SoftTimeLimitExceeded

@celery_app.task(
    soft_time_limit=270,   # warn at 4.5 min
    time_limit=300,        # hard kill at 5 min
    bind=True,
    max_retries=3,
)
def run_attack_surface_task(self, ctx_dict: dict):
    ctx = ScanContext(**ctx_dict)
    partial_findings: list[UnifiedFinding] = []

    try:
        for step_fn, step_name in SURFACE_PIPELINE_STEPS:
            step_findings = step_fn(ctx)
            partial_findings.extend(step_findings)
            update_scan_progress(ctx.scan_id, step_name)

    except SoftTimeLimitExceeded:
        # Save what we have before hard kill
        write_partial_findings(ctx.scan_id, partial_findings, status="partial")
        post_scan_status(ctx, status="partial", message="Attack surface scan timed out — partial results available")
        return  # don't re-raise; partial is acceptable

    write_final_findings(ctx.scan_id, partial_findings, status="completed")
```

### 28.7 Log Levels and Format

```python
# sentinel/logging_config.py

LOG_FORMAT = "%(asctime)s %(levelname)-8s %(name)s scan_id=%(scan_id)s %(message)s"

LOG_LEVEL_RULES = {
    "DEBUG":   ["LLM prompt text (truncated 500 chars)", "Raw OSV API response", "tree-sitter parse output"],
    "INFO":    ["Scan started/completed", "Stage started/completed", "Finding emitted (title + severity)", "Cache hit/miss"],
    "WARNING": ["Module partial failure", "External tool not found", "LLM malformed response (reprompted)", "OSV stale cache used"],
    "ERROR":   ["Module failed entirely", "LLM failed after retries", "Webhook HMAC validation failure", "DB write failure"],
}

# Structured logging (structlog) emits JSON in production, colored text in dev:
import structlog

log = structlog.get_logger()

# Usage in workers:
log.info("scan.stage.started",
    scan_id=str(ctx.scan_id),
    stage="code_security",
    pr=ctx.pr.pr_number if ctx.pr else None,
    repo=f"{ctx.repo.owner}/{ctx.repo.name}",
)

log.warning("llm.malformed_response",
    scan_id=str(ctx.scan_id),
    attempt=attempt,
    raw_preview=raw[:200],
)
```

---

## 29. Local Development Setup

### 29.1 `pyproject.toml` structure

```toml
[build-system]
requires = ["hatchling>=1.27.0"]
build-backend = "hatchling.build"

[project]
name = "sentinel"
version = "0.1.0"
description = "Defender-facing attack surface, dependency risk, and semantic code security scanner"
readme = "README.md"
requires-python = ">=3.12"
dependencies = [
  "fastapi>=0.115.0,<1.0.0",
  "uvicorn[standard]>=0.35.0,<1.0.0",
  "sqlalchemy>=2.0.38,<3.0.0",
  "alembic>=1.16.0,<2.0.0",
  "psycopg[binary]>=3.2.0,<4.0.0",
  "redis>=6.0.0,<7.0.0",
  "celery>=5.5.0,<6.0.0",
  "pydantic>=2.11.0,<3.0.0",
  "pydantic-settings>=2.8.0,<3.0.0",
  "httpx>=0.28.0,<1.0.0",
  "dnspython>=2.7.0,<3.0.0",
  "orjson>=3.10.0,<4.0.0",
  "click>=8.1.8,<9.0.0",
  "rich>=14.0.0,<15.0.0",
  "python-dotenv>=1.1.0,<2.0.0",
  "anthropic>=0.50.0,<1.0.0",
  "tree-sitter>=0.24.0,<1.0.0",
  "tree-sitter-python>=0.23.0,<1.0.0",
  "tree-sitter-javascript>=0.23.0,<1.0.0",
  "tree-sitter-typescript>=0.23.0,<1.0.0",
]

[project.optional-dependencies]
dev = [
  "pytest>=8.3.5,<9.0.0",
  "pytest-asyncio>=0.26.0,<1.0.0",
  "pytest-cov>=6.1.0,<7.0.0",
  "mypy>=1.15.0,<2.0.0",
  "ruff>=0.11.0,<1.0.0",
  "pre-commit>=4.2.0,<5.0.0",
  "respx>=0.22.0,<1.0.0",
  "factory-boy>=3.3.3,<4.0.0",
  "faker>=37.1.0,<38.0.0",
]

attack-surface = [
  "shodan>=1.31.0,<2.0.0",
]

[project.scripts]
sentinel = "sentinel.cli.main:cli"

[tool.hatch.build.targets.wheel]
packages = ["sentinel"]

[tool.pytest.ini_options]
minversion = "8.0"
addopts = "-q --strict-markers --disable-warnings"
testpaths = ["tests"]
asyncio_mode = "auto"
markers = [
  "slow: requires network or heavyweight fixtures",
  "llm: exercises prompt / response normalization",
  "integration: uses live postgres/redis containers",
]

[tool.ruff]
line-length = 100
target-version = "py312"
src = ["sentinel", "tests"]

[tool.ruff.lint]
select = ["E", "F", "I", "B", "UP", "SIM"]
ignore = ["B008"]

[tool.ruff.format]
quote-style = "double"
indent-style = "space"

[tool.mypy]
python_version = "3.12"
strict = true
warn_unused_ignores = true
warn_redundant_casts = true
disallow_any_generics = true
pretty = true
packages = ["sentinel"]

[tool.coverage.run]
source = ["sentinel"]
branch = true

[tool.coverage.report]
skip_covered = true
show_missing = true
```

### 29.2 Local full-stack run via Docker Compose

Run everything needed for local development with one command:

```yaml
# docker-compose.yml
version: "3.9"

services:
  postgres:
    image: postgres:18
    container_name: sentinel-postgres
    environment:
      POSTGRES_USER: sentinel
      POSTGRES_PASSWORD: sentinel
      POSTGRES_DB: sentinel
    ports:
      - "5432:5432"
    volumes:
      - sentinel-postgres-data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U sentinel -d sentinel"]
      interval: 5s
      timeout: 5s
      retries: 20

  redis:
    image: redis:8
    container_name: sentinel-redis
    ports:
      - "6379:6379"
    command: ["redis-server", "--appendonly", "yes"]
    volumes:
      - sentinel-redis-data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 20

  api:
    image: python:3.12-slim
    container_name: sentinel-api
    working_dir: /app
    env_file:
      - .env
    environment:
      DATABASE_URL: postgresql+psycopg://sentinel:sentinel@postgres:5432/sentinel
      REDIS_URL: redis://redis:6379/0
      CELERY_BROKER_URL: redis://redis:6379/0
      CELERY_RESULT_BACKEND: redis://redis:6379/1
      DASHBOARD_URL: http://localhost:3000
      SENTINEL_ENV: local
    volumes:
      - ./:/app
    command: >
      bash -lc "
      pip install -e .[dev] &&
      alembic upgrade head &&
      uvicorn sentinel.api.main:app --host 0.0.0.0 --port 8000 --reload
      "
    ports:
      - "8000:8000"
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy

  worker:
    image: python:3.12-slim
    container_name: sentinel-worker
    working_dir: /app
    env_file:
      - .env
    environment:
      DATABASE_URL: postgresql+psycopg://sentinel:sentinel@postgres:5432/sentinel
      REDIS_URL: redis://redis:6379/0
      CELERY_BROKER_URL: redis://redis:6379/0
      CELERY_RESULT_BACKEND: redis://redis:6379/1
      SENTINEL_ENV: local
    volumes:
      - ./:/app
    command: >
      bash -lc "
      pip install -e .[dev] &&
      celery -A sentinel.workers.celery_app worker --loglevel=info -Q high_priority,default,low_priority,scheduled
      "
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy

  scheduler:
    image: python:3.12-slim
    container_name: sentinel-scheduler
    working_dir: /app
    env_file:
      - .env
    environment:
      DATABASE_URL: postgresql+psycopg://sentinel:sentinel@postgres:5432/sentinel
      REDIS_URL: redis://redis:6379/0
      CELERY_BROKER_URL: redis://redis:6379/0
      CELERY_RESULT_BACKEND: redis://redis:6379/1
      SENTINEL_ENV: local
    volumes:
      - ./:/app
    command: >
      bash -lc "
      pip install -e .[dev] &&
      celery -A sentinel.workers.celery_app beat --loglevel=info
      "
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy

  dashboard:
    image: node:22-bookworm
    container_name: sentinel-dashboard
    working_dir: /app/dashboard
    environment:
      NEXT_PUBLIC_SENTINEL_API_BASE: http://localhost:8000
      PORT: 3000
    volumes:
      - ./:/app
    command: >
      bash -lc "
      corepack enable &&
      npm install &&
      npm run dev -- --hostname 0.0.0.0 --port 3000
      "
    ports:
      - "3000:3000"
    depends_on:
      api:
        condition: service_started

volumes:
  sentinel-postgres-data:
  sentinel-redis-data:
```

Start the stack:

```bash
docker compose up --build
```

Local endpoints:

- API: `http://localhost:8000`
- API docs: `http://localhost:8000/docs`
- Dashboard: `http://localhost:3000`
- Postgres: `localhost:5432`
- Redis: `localhost:6379`

### 29.3 Run modules standalone for fast iteration

For API-only iteration:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
alembic upgrade head
uvicorn sentinel.api.main:app --reload --port 8000
```

For worker-only iteration:

```bash
source .venv/bin/activate
celery -A sentinel.workers.celery_app worker --loglevel=info -Q high_priority,default
```

For scheduler-only iteration:

```bash
source .venv/bin/activate
celery -A sentinel.workers.celery_app beat --loglevel=info
```

For dashboard-only iteration:

```bash
cd dashboard
corepack enable
npm install
npm run dev
```

For CLI-only iteration against a local repo checkout:

```bash
source .venv/bin/activate
sentinel scan --repo /absolute/path/to/repo --module deps
sentinel scan --repo /absolute/path/to/repo --module code_security
sentinel surface --domain example.com
```

For a single service module from Python without webhooks:

```bash
python -m sentinel.tools.run_dep_scan --repo /tmp/demo-repo
python -m sentinel.tools.run_code_security --repo /tmp/demo-repo --pr-diff tests/fixtures/diffs/idor.patch
python -m sentinel.tools.run_surface_scan --domain example.com
```

### 29.4 Test fixtures and mock data layout

```text
tests/
  fixtures/
    osv/
      pypi/
        requests_2.26.0.json
        urllib3_1.26.6.json
      npm/
        axios_0.27.2.json
      bulk/
        pypi_snapshot_minimal.json
        npm_snapshot_minimal.json
    diffs/
      code_security/
        access_control/
          fastapi_missing_dep.patch
          express_admin_bypass.patch
        injection/
          sqlalchemy_text_concat.patch
        ssrf/
          nextjs_user_url_fetch.patch
        false_positive/
          yaml_safe_load_not_ssrf.patch
    repos/
      fastapi_demo/
      express_demo/
```

Rules:

- Mock OSV responses live under `tests/fixtures/osv/<ecosystem>/`. Each file mirrors the OSV `/v1/query` response body for one package+version.
- Diff fixtures live under `tests/fixtures/diffs/code_security/<category>/`.
- False-positive regression fixtures must live under `tests/fixtures/diffs/code_security/false_positive/`.

How to add a new diff fixture:

1. Add the smallest possible patch file under the matching category directory.
2. Add any supporting mini repo under `tests/fixtures/repos/<fixture_name>/` if the parser needs framework context.
3. Add an expected normalized findings file beside it, e.g. `fastapi_missing_dep.expected.json`.
4. Add a test that asserts both detection and suppression behavior.

```python
def test_fastapi_missing_dep_fixture(snapshot_json):
    result = run_code_security_fixture(
        diff_path="tests/fixtures/diffs/code_security/access_control/fastapi_missing_dep.patch",
        repo_fixture="tests/fixtures/repos/fastapi_demo",
    )
    assert result.findings == snapshot_json("fastapi_missing_dep.expected.json")
```

### 29.5 `.env.example` for local development

```dotenv
# .env.example
SENTINEL_ENV=local
LOG_LEVEL=DEBUG

# Core infra
DATABASE_URL=postgresql+psycopg://sentinel:sentinel@localhost:5432/sentinel
REDIS_URL=redis://localhost:6379/0
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/1

# API / dashboard
API_HOST=0.0.0.0
API_PORT=8000
DASHBOARD_URL=http://localhost:3000
DASHBOARD_PORT=3000
DASHBOARD_AUTO_OPEN=false

# GitHub integration
GITHUB_APP_ID=
GITHUB_APP_PRIVATE_KEY=
GITHUB_WEBHOOK_SECRET=
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=
GITHUB_TOKEN=

# LLM providers
ANTHROPIC_API_KEY=
LLM_PROVIDER=anthropic
LLM_MODEL=claude-sonnet-4-6

# Attack surface
SHODAN_API_KEY=
DEFAULT_DOMAIN_SEEDS=

# Storage
ARTIFACTS_DIR=./.sentinel-artifacts
REPORTS_DIR=./sentinel-report

# Feature flags
ENABLE_ATTACK_SURFACE=true
ENABLE_DEP_RISK=true
ENABLE_CODE_SECURITY=true
ENABLE_GITHUB_APP=false
```

Local rule: `.env` is for secrets and environment-specific values. `sentinel.yml` is for non-secret feature configuration only.

### 29.6 Pre-commit hooks

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.11.8
    hooks:
      - id: ruff-check
        args: ["--fix"]
      - id: ruff-format

  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.15.0
    hooks:
      - id: mypy
        additional_dependencies:
          - pydantic>=2.11.0
          - sqlalchemy>=2.0.38
        args: ["--config-file=pyproject.toml"]

  - repo: local
    hooks:
      - id: pytest-fast
        name: pytest fast suite
        entry: pytest -m "not slow and not integration" -q
        language: system
        pass_filenames: false
```

Install once:

```bash
pip install -e .[dev]
pre-commit install
pre-commit run --all-files
```

### 29.7 How to add a new ecosystem parser

The extension point is the parser registry described in §24.

Step-by-step:

1. Create a parser module, e.g. `sentinel/deps/parsers/go.py`.
2. Implement the `EcosystemParser` protocol: `ecosystem`, `manifest_patterns`, `parse()`, and `build_dep_graph()`.
3. Normalize package names to the OSV ecosystem naming used by `cve_cache`.
4. Register the parser in `sentinel/deps/parsers/__init__.py`.
5. Add fixture manifests under `tests/fixtures/manifests/<ecosystem>/`.
6. Add parser unit tests and one end-to-end dep risk test.
7. Add the ecosystem to nightly bulk sync only after parser output is stable.
8. Update dashboard filters and API enum validation.

```python
# sentinel/deps/parsers/go.py
from sentinel.deps.models import DepGraph, PackageRef

class GoParser:
    ecosystem = "go"
    manifest_patterns = ["go.mod", "go.sum"]

    def parse(self, manifest_path: str) -> list[PackageRef]:
        return parse_go_mod(manifest_path)

    def build_dep_graph(self, manifest_path: str) -> DepGraph:
        pkgs = self.parse(manifest_path)
        return dep_graph_from_go_modules(pkgs)
```

```python
# sentinel/deps/parsers/__init__.py
from sentinel.deps.parsers.go import GoParser
from sentinel.deps.registry import register_parser

register_parser(GoParser())
```

Minimum tests before merging a new parser:

- parses a direct dependency
- parses a transitive dependency
- normalizes the package name the same way OSV expects
- produces a stable `DepGraph`
- survives malformed manifests with a partial result, not a crash

---

## 30. Migration Guide: `auth_findings` → `code_security_findings`

### 30.1 Migration intent

`auth_findings` was too narrow once Module 3 expanded beyond access control. The replacement table is `code_security_findings`, which stores all semantic code-security categories while preserving access-control findings as `category='access_control'`.

### 30.2 Exact Alembic migration

```python
"""migrate auth_findings to code_security_findings

Revision ID: 20260415_01_code_security_findings
Revises: 20260415_00_initial
Create Date: 2026-04-15 09:00:00.000000
"""

from alembic import op
import sqlalchemy as sa

revision = "20260415_01_code_security_findings"
down_revision = "20260415_00_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "code_security_findings",
        sa.Column("id", sa.UUID(), primary_key=True, nullable=False),
        sa.Column("scan_id", sa.UUID(), sa.ForeignKey("scans.id"), nullable=True),
        sa.Column("repo_id", sa.UUID(), sa.ForeignKey("repos.id"), nullable=True),
        sa.Column("pr_number", sa.Integer(), nullable=False),
        sa.Column("commit_sha", sa.Text(), nullable=False),
        sa.Column("category", sa.Text(), nullable=False),
        sa.Column("issue_type", sa.Text(), nullable=False),
        sa.Column("route", sa.Text(), nullable=True),
        sa.Column("method", sa.Text(), nullable=True),
        sa.Column("file", sa.Text(), nullable=False),
        sa.Column("line", sa.Integer(), nullable=True),
        sa.Column("cwe_id", sa.Integer(), nullable=True),
        sa.Column("severity", sa.Text(), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("fix_suggestion", sa.Text(), nullable=True),
        sa.Column("resolved", sa.Boolean(), nullable=False, server_default=sa.text("FALSE")),
        sa.Column("resolved_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("llm_model", sa.Text(), nullable=True),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False, server_default=sa.text("NOW()")),
    )

    op.create_index(
        "ix_code_security_findings_repo_pr",
        "code_security_findings",
        ["repo_id", "pr_number"],
    )
    op.create_index(
        "ix_code_security_findings_repo_category_resolved",
        "code_security_findings",
        ["repo_id", "category", "resolved"],
    )

    op.execute(
        """
        DO $$
        BEGIN
          IF to_regclass('public.auth_findings') IS NOT NULL THEN
            INSERT INTO code_security_findings (
              id, scan_id, repo_id, pr_number, commit_sha,
              category, issue_type, route, method, file, line,
              cwe_id, severity, explanation, fix_suggestion,
              resolved, resolved_at, llm_model, created_at
            )
            SELECT
              id, scan_id, repo_id, pr_number, commit_sha,
              'access_control' AS category,
              COALESCE(issue_type, 'missing_auth') AS issue_type,
              route, method, file, line, cwe_id, severity,
              explanation, fix_suggestion,
              COALESCE(resolved, FALSE),
              resolved_at, llm_model,
              COALESCE(created_at, NOW())
            FROM auth_findings;
          END IF;
        END $$;
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
          IF to_regclass('public.auth_findings') IS NULL THEN
            CREATE TABLE auth_findings (
              id UUID PRIMARY KEY,
              scan_id UUID REFERENCES scans(id),
              repo_id UUID REFERENCES repos(id),
              pr_number INT NOT NULL,
              commit_sha TEXT NOT NULL,
              issue_type TEXT,
              route TEXT,
              method TEXT,
              file TEXT NOT NULL,
              line INT,
              cwe_id INT,
              severity TEXT NOT NULL,
              explanation TEXT NOT NULL,
              fix_suggestion TEXT,
              resolved BOOLEAN DEFAULT FALSE,
              resolved_at TIMESTAMPTZ,
              llm_model TEXT,
              created_at TIMESTAMPTZ DEFAULT NOW()
            );
          END IF;

          INSERT INTO auth_findings (
            id, scan_id, repo_id, pr_number, commit_sha,
            issue_type, route, method, file, line, cwe_id,
            severity, explanation, fix_suggestion,
            resolved, resolved_at, llm_model, created_at
          )
          SELECT
            id, scan_id, repo_id, pr_number, commit_sha,
            issue_type, route, method, file, line, cwe_id,
            severity, explanation, fix_suggestion,
            resolved, resolved_at, llm_model, created_at
          FROM code_security_findings
          WHERE category = 'access_control'
          ON CONFLICT (id) DO NOTHING;
        END $$;
        """
    )

    op.drop_index("ix_code_security_findings_repo_category_resolved", table_name="code_security_findings")
    op.drop_index("ix_code_security_findings_repo_pr", table_name="code_security_findings")
    op.drop_table("code_security_findings")
```

### 30.3 Data mapping

| `auth_findings` | `code_security_findings` | Notes |
|-----------------|--------------------------|-------|
| `id` | `id` | Preserved |
| `scan_id` | `scan_id` | Preserved |
| `repo_id` | `repo_id` | Preserved |
| `pr_number` | `pr_number` | Preserved |
| `commit_sha` | `commit_sha` | Preserved |
| `issue_type` | `issue_type` | Backfill to `'missing_auth'` if null |
| `route` | `route` | Preserved |
| `method` | `method` | Preserved |
| `file` | `file` | Preserved |
| `line` | `line` | Preserved |
| `cwe_id` | `cwe_id` | Preserved |
| `severity` | `severity` | Preserved |
| `explanation` | `explanation` | Preserved |
| `fix_suggestion` | `fix_suggestion` | Preserved |
| `resolved` | `resolved` | Preserved, default `FALSE` if null |
| `resolved_at` | `resolved_at` | Preserved |
| `llm_model` | `llm_model` | Preserved |
| `created_at` | `created_at` | Preserved, backfill `NOW()` if null |
| n/a | `category` | Backfilled to `'access_control'` for all legacy rows |

Backfill policy:

- Every legacy row becomes a first-class code-security finding.
- No legacy row is dropped.
- The migration is additive first; table removal is a later cleanup step after API deprecation completes.

### 30.4 API backward compatibility

For one deprecation window, `/auth` remains callable but redirects to `/code-security`.

```python
from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse

router = APIRouter()

@router.get("/api/v1/repos/{repo_id}/auth", include_in_schema=False)
async def legacy_auth_findings(repo_id: str, request: Request):
    query = request.url.query
    target = f"/api/v1/repos/{repo_id}/code-security"
    if query:
        target = f"{target}?{query}"
    return RedirectResponse(url=target, status_code=308)
```

Response contract:

- Status code: `308 Permanent Redirect`
- Query string preserved
- Response header: `Deprecation: true`
- Response header: `Sunset: Tue, 01 Sep 2026 00:00:00 GMT`

### 30.5 How to verify migration correctness

Row-count parity for legacy access-control data:

```sql
SELECT
  (SELECT COUNT(*) FROM auth_findings) AS auth_count,
  (SELECT COUNT(*) FROM code_security_findings WHERE category = 'access_control') AS migrated_count;
```

No missing IDs:

```sql
SELECT a.id
FROM auth_findings a
LEFT JOIN code_security_findings c ON c.id = a.id
WHERE c.id IS NULL;
```

Sample semantic check:

```sql
SELECT
  c.id,
  c.category,
  c.issue_type,
  c.file,
  c.line,
  c.severity
FROM code_security_findings c
WHERE c.category = 'access_control'
ORDER BY c.created_at DESC
LIMIT 20;
```

Expected result:

- `auth_count = migrated_count`
- "missing IDs" query returns zero rows
- All migrated rows have `category = 'access_control'`

### 30.6 Deprecation timeline

- `2026-04-15`: `code_security_findings` ships; `/code-security` becomes canonical.
- `2026-05-15`: API responses from `/auth` include deprecation and sunset headers.
- `2026-07-01`: Dashboard and CLI stop linking to `/auth`; only `/code-security` appears in docs and UI.
- `2026-09-01`: `/api/v1/repos/{repo_id}/auth` redirect is removed from the public API.
- `2026-10-01`: `auth_findings` table may be dropped in a follow-up migration if no rollback requirement remains.

---

## 31. Signal/Noise Reduction: Production Heuristics

### 31.1 Auto-suppression heuristics in v1

The LLM is not allowed to emit a finding directly to the user without deterministic post-filtering. v1 suppresses the following patterns by default:

| Pattern | Category suppressed | Suppression rule |
|---------|---------------------|------------------|
| `yaml.safe_load(...)` flagged as SSRF | `ssrf` | Suppress; reclassify as safe deserialization helper |
| `subprocess.run([...], shell=False)` with list args only | `injection` | Suppress unless untrusted input is joined into a string before the call |
| SQLAlchemy parameterized query (`text(...), {"id": user_id}`) | `injection` | Suppress unless string concatenation occurs before query construction |
| Constant-host fetch (`requests.get("https://api.stripe.com/...")`) | `ssrf` | Suppress if URL host is static and not user-controlled |
| Framework-native auth dependency present (`Depends(require_admin)`, `@login_required`, `router.use(requireAuth)`) | `access_control` | Suppress missing-auth findings unless a bypass path exists in the same diff |
| `hashlib.sha256`, `bcrypt`, `scrypt`, `argon2` flagged as weak crypto | `crypto_tls` | Suppress |
| `jwt.decode(..., algorithms=[...])` with verification enabled | `crypto_tls` | Suppress |
| Internal test files, fixtures, migrations, and examples | all | Suppress paths matching `tests/`, `fixtures/`, `examples/`, `migrations/versions/` unless `--include-non-prod` is set |
| Generated files | all | Suppress paths matching `*.min.js`, `dist/`, `build/`, `coverage/`, `node_modules/` |

Reference implementation:

```python
AUTO_SUPPRESS_PATHS = (
    "tests/", "fixtures/", "examples/", "dist/", "build/",
    "coverage/", "node_modules/", "migrations/versions/",
)

def should_auto_suppress(finding: CodeSecurityFinding, code_excerpt: str) -> tuple[bool, str | None]:
    if finding.file.startswith(AUTO_SUPPRESS_PATHS):
        return True, "non_prod_or_generated_path"

    if finding.category == "ssrf" and "yaml.safe_load(" in code_excerpt:
        return True, "safe_yaml_not_ssrf"

    if finding.category == "injection" and "subprocess.run([" in code_excerpt and "shell=True" not in code_excerpt:
        return True, "argv_exec_without_shell"

    if finding.category == "ssrf" and has_constant_allowlisted_host(code_excerpt):
        return True, "constant_allowlisted_host"

    if finding.category == "access_control" and framework_guard_present(code_excerpt):
        return True, "framework_auth_guard_present"

    return False, None
```

### 31.2 Confidence scoring by `(category, framework)` pair

Every finding gets a numeric score from `0.0` to `1.0` before severity gating.

```python
FRAMEWORK_CATEGORY_PRIORS = {
    "fastapi": {
        "access_control": 0.62,
        "injection": 0.58,
        "secrets": 0.92,
        "ssrf": 0.46,
        "deserialization": 0.63,
        "crypto_tls": 0.57,
    },
    "flask": {
        "access_control": 0.56,
        "injection": 0.60,
        "secrets": 0.92,
        "ssrf": 0.49,
        "deserialization": 0.61,
        "crypto_tls": 0.55,
    },
    "django": {
        "access_control": 0.64,
        "injection": 0.67,
        "secrets": 0.92,
        "ssrf": 0.44,
        "deserialization": 0.59,
        "crypto_tls": 0.53,
    },
    "express": {
        "access_control": 0.60,
        "injection": 0.57,
        "secrets": 0.92,
        "ssrf": 0.48,
        "deserialization": 0.54,
        "crypto_tls": 0.51,
    },
    "nextjs_api": {
        "access_control": 0.57,
        "injection": 0.52,
        "secrets": 0.92,
        "ssrf": 0.51,
        "deserialization": 0.46,
        "crypto_tls": 0.50,
    },
    "generic_python": {
        "access_control": 0.45,
        "injection": 0.48,
        "secrets": 0.92,
        "ssrf": 0.40,
        "deserialization": 0.52,
        "crypto_tls": 0.48,
    },
    "generic_node": {
        "access_control": 0.44,
        "injection": 0.47,
        "secrets": 0.92,
        "ssrf": 0.41,
        "deserialization": 0.45,
        "crypto_tls": 0.47,
    },
}
```

Adjustment formula:

```python
def score_finding(base: float, *, sink_match: bool, source_match: bool,
                  safe_pattern_hit: bool, llm_certainty: float,
                  cross_file_support: bool, repeated_fp_penalty: float) -> float:
    score = base
    if sink_match:
        score += 0.14
    if source_match:
        score += 0.10
    if cross_file_support:
        score += 0.08
    score += min(llm_certainty, 0.12)
    if safe_pattern_hit:
        score -= 0.25
    score -= repeated_fp_penalty
    return max(0.0, min(score, 1.0))
```

Production thresholds:

- `score >= 0.85`: emit as `confidence="high"`
- `0.70 <= score < 0.85`: emit as `confidence="medium"`
- `0.55 <= score < 0.70`: emit only in dashboard/JSON, not PR annotation
- `score < 0.55`: suppress by default

### 31.3 False-positive feedback loop

When a developer marks a finding as false positive:

1. Persist feedback against the normalized `dedupe_key`.
2. Increment `false_positive_count` for that exact pattern.
3. Decrease future confidence for matching findings by `0.05` per confirmed false positive, capped at `0.25`.
4. Auto-suppress once both conditions are true:
   - at least `3` false-positive confirmations
   - false-positive ratio is `>= 0.80` over the last `20` matching findings

```python
AUTO_SUPPRESS_MIN_FALSE_POSITIVES = 3
AUTO_SUPPRESS_MIN_SAMPLE_SIZE = 20
AUTO_SUPPRESS_RATIO = 0.80
MAX_FP_PENALTY = 0.25
```

Operational behavior:

- The first few reports still appear, but with reduced confidence.
- After the threshold is crossed, matching findings are hidden from PR comments and checks.
- Suppressed findings are still written to raw artifacts for auditability.

### 31.4 Known high-false-positive patterns

| Pattern | Common wrong label | v1 handling |
|---------|--------------------|-------------|
| `yaml.safe_load(body)` | `ssrf` | Suppress and record `safe_yaml_not_ssrf` |
| `requests.get(settings.SERVICE_URL)` where `SERVICE_URL` is constant config | `ssrf` | Suppress if config source is constant or allowlisted |
| `subprocess.run(["git", "status"], shell=False)` | `command_injection` | Suppress |
| `session.execute(text("select * from users where id=:id"), {"id": uid})` | `sql_injection` | Suppress |
| `jwt.decode(token, key, algorithms=["HS256"])` | `weak_crypto` | Suppress unless `verify_signature=False` or equivalent |
| `hashlib.sha256(...)` | `weak_crypto` | Suppress |
| admin route protected by framework guard in a shared dependency | `missing_auth` | Suppress if guard resolution succeeds across file boundaries |

If a pattern is noisy but not fully suppressible, Sentinel should downgrade it to dashboard-only instead of creating a PR annotation.

### 31.5 Deduplication across scan runs

Findings are deduplicated across scans using a stable fingerprint, not raw row identity.

```python
import hashlib

def build_dedupe_key(f: CodeSecurityFinding) -> str:
    normalized_path = f.file.lower()
    normalized_line_bucket = (f.line or 0) // 3
    route = (f.route or "").lower()
    method = (f.method or "").upper()
    payload = "|".join([
        f.repo_id,
        f.category,
        f.issue_type,
        normalized_path,
        str(normalized_line_bucket),
        route,
        method,
    ])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
```

Strategy:

- Same `dedupe_key` within `30` days: update `last_seen_at`, `occurrence_count`, and latest `scan_id`.
- Line movements within a small range do not create a new finding.
- A severity change updates the existing logical finding instead of creating a duplicate alert.
- A finding is considered resolved only after it is absent from `2` consecutive scans on the same branch or PR head lineage.

```sql
SELECT
  dedupe_key,
  COUNT(*) AS row_count,
  MIN(created_at) AS first_seen,
  MAX(created_at) AS last_seen
FROM code_security_finding_events
GROUP BY dedupe_key
HAVING COUNT(*) > 1
ORDER BY row_count DESC, last_seen DESC;
```

Recommended event model:

- `code_security_findings`: current logical state
- `code_security_finding_events`: per-scan observations for history and feedback learning

This keeps the user-facing dashboard stable while preserving full audit history.
