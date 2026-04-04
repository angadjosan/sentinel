# Sentinel — Defender Attack Surface, Exploitability-Aware Dependencies & Semantic LLM Code Security
## Product Requirements & Technical Design Document

**Version:** 0.2  
**Date:** 2026-04-04  
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
