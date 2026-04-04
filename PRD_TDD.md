# Sentinel — AI-Powered Attack Surface & Code Security Monitor
## Product Requirements & Technical Design Document

**Version:** 0.1  
**Date:** 2026-04-03  
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
9. [Module 3 — AI Code Review for Auth Flaws](#9-module-3--ai-code-review-for-auth-flaws)
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

Modern engineering teams have three blind spots that live in separate tools (or no tool at all):

1. **What attack surface does this repo actually expose on the internet?** Subdomains, endpoints, TLS configs, dangling DNS — nobody has a live, repo-linked picture of this.
2. **Which vulnerable dependencies are actually reachable?** Scanners like Dependabot flag thousands of CVEs, most unreachable. Teams tune them out. The signal-to-noise is terrible.
3. **Does this new API route have auth?** Code review misses broken access control constantly. IDOR bugs ship because reviewers don't trace the full middleware chain.

These three questions share a root: *what can an attacker actually reach and exploit?* Sentinel answers all three from a single GitHub integration, unified into one risk surface per repo.

---

## 2. Product Goals & Non-Goals

### Goals

- **G1.** One-click GitHub App install — zero config to get value on an existing repo.
- **G2.** Attack surface enumeration tied to a specific repo/org, updated on push to main.
- **G3.** Dependency risk scoring that weights CVEs by reachability, not just existence.
- **G4.** AI-powered PR review that flags missing/misconfigured auth on new routes before merge.
- **G5.** Web dashboard and CLI that surface findings in a digestible, shareable format.
- **G6.** High demo value — findings should be dramatic and explainable in a tweet.

### Non-Goals (v1)

- **NG1.** Automated exploitation or active fuzzing (passive enumeration only).
- **NG2.** Non-GitHub SCM support (GitLab, Bitbucket) — out of scope for v1.
- **NG3.** Multi-language deep static analysis beyond Python and JavaScript/TypeScript in v1.
- **NG4.** SAST beyond auth/access-control patterns — not a general code scanner.
- **NG5.** Scanning arbitrary GitHub repos without install (saved for v2 "public scanner" feature).

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

### User Flow 2 — PR Opened with New API Route

```
Dev opens PR: "feat: add /api/admin/users endpoint"
  → GitHub sends pull_request webhook (action: opened/synchronize)
  → Sentinel receives webhook
  → Diff extraction: identify new/modified files
  → Route detection: find new route definitions in diff
  → Auth middleware context: fetch existing auth patterns from repo
  → Claude prompt: "Does this route have proper auth? IDOR risks?"
  → Claude returns structured JSON: [{ route, issue_type, severity, explanation }]
  → Sentinel posts GitHub Check Run (status: action_required) + PR comment
  → Developer sees inline annotation: "⚠ /api/admin/users has no auth middleware — potential IDOR"
  → Dev fixes it, pushes
  → Sentinel re-reviews, posts: "✓ Auth check: no issues found"
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
      → "Auth Review" tab:
          - PR history with review results
          - Open issues (unfixed routes)
          - Auth middleware map (what patterns we detected)
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
│  │  Attack Surface  │  │  Dep Risk Score │  │   AI Review   │  │
│  │  Worker          │  │  Worker         │  │   Worker      │  │
│  │                  │  │                 │  │               │  │
│  │  subfinder       │  │  dep parser     │  │  diff parser  │  │
│  │  httpx           │  │  OSV.dev cache  │  │  route detect │  │
│  │  shodan API      │  │  reachability   │  │  Claude API   │  │
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

| Event | Attack Surface | Dep Risk | AI Code Review |
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
- **AI review** fires on every PR push — this is the most latency-sensitive, must complete before PR review window.

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
Given a GitHub repo, determine what infrastructure it exposes on the internet.

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
Score each dependency not just by "does a CVE exist" but by "is the vulnerable code path actually reachable from this repo."

### Dependency Parsers

Support matrix (v1):

| Ecosystem | Files | Parser |
|-----------|-------|--------|
| Python | `requirements.txt`, `Pipfile.lock`, `pyproject.toml` | custom regex + `tomllib` |
| Node.js | `package.json`, `package-lock.json`, `yarn.lock` | `npm list --json` equivalent |
| (v2) Go | `go.mod`, `go.sum` | go mod graph |
| (v2) Rust | `Cargo.lock` | toml parser |

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

## 9. Module 3 — AI Code Review for Auth Flaws

### Goal
On every PR, detect new API routes/endpoints that are missing authentication, have incorrect authorization checks, or are susceptible to IDOR.

### Route Detection (Static Analysis)

**Step 1: Detect framework**

Heuristics based on imports in changed files:
```python
FRAMEWORK_SIGNATURES = {
    "fastapi":  ["from fastapi import", "APIRouter", "@app.get", "@router."],
    "flask":    ["from flask import Flask", "@app.route", "Blueprint"],
    "express":  ["require('express')", "router.get(", "app.post("],
    "django":   ["urlpatterns", "path(", "include("],
    "nextjs":   ["export default function handler", "export async function GET"],
    "gin":      ["gin.Default()", "r.GET(", "r.POST("],
}
```

**Step 2: Extract new routes from diff**

Parse git diff, find added lines matching route pattern for detected framework.

```python
def extract_routes_from_diff(diff: str, framework: str) -> List[RouteInfo]:
    # Uses tree-sitter to parse changed files, not just line-level grep
    # Gives us: method, path pattern, handler function name, file+line
    ...
```

**Step 3: Gather auth context**

```python
def get_auth_context(repo: Repo, framework: str) -> AuthContext:
    # Find existing auth middleware/decorators in the repo:
    # - Search for @require_auth, @login_required, Depends(get_current_user), etc.
    # - Read the middleware file contents (not just names)
    # - Find examples of correctly-protected routes in the existing codebase
    # - Detect auth pattern: JWT, session, API key, OAuth, custom
    ...
```

**Step 4: Claude prompt construction**

```python
SYSTEM_PROMPT = """
You are a security engineer reviewing a pull request for authentication and authorization flaws.
You will be given:
1. New API routes being added
2. The existing auth middleware/decorators used in this codebase
3. Examples of correctly-protected routes in this codebase

Identify:
- Routes missing authentication entirely
- Routes where the authenticated user can access other users' resources (IDOR)
- Routes where privilege level checks are missing or incorrect
- Routes where auth logic is reimplemented inline instead of using the established middleware

For each issue, return:
{
  "route": "POST /api/users/{id}/settings",
  "file": "src/routes/users.py",
  "line": 142,
  "issue_type": "idor" | "missing_auth" | "broken_access_control" | "auth_bypass",
  "severity": "critical" | "high" | "medium",
  "explanation": "...",
  "fix_suggestion": "..."
}

Return a JSON array. If no issues, return [].
Be precise. Do not flag correctly-protected routes.
"""

def build_pr_review_prompt(routes: List[RouteInfo], auth_context: AuthContext, diff: str) -> str:
    return f"""
Codebase auth pattern: {auth_context.pattern}

Existing auth middleware (read this carefully):
```python
{auth_context.middleware_code[:3000]}
```

Examples of correctly-protected routes in this codebase:
```
{auth_context.examples[:2000]}
```

New routes being added in this PR:
```
{format_routes(routes)}
```

Relevant diff:
```diff
{diff[:6000]}
```

Review for auth flaws. Return JSON array only.
"""
```

**Step 5: Post results to GitHub**

```python
def post_pr_review(pr: PullRequest, findings: List[AuthFinding]) -> None:
    if not findings:
        # Post passing check run
        create_check_run(pr, conclusion="success", title="Sentinel Auth Review: No issues")
        return
    
    # Create Check Run (shows in PR checks bar)
    create_check_run(pr, conclusion="action_required",
                     title=f"Sentinel: {len(findings)} auth issue(s) found",
                     annotations=[finding_to_annotation(f) for f in findings])
    
    # Post summary comment
    post_pr_comment(pr, build_summary_comment(findings))
```

GitHub Check Run annotations appear as inline comments on the specific lines — highest-signal delivery mechanism.

### Auth Finding Output Schema

```python
@dataclass
class AuthFinding:
    route: str
    method: str
    file: str
    line: int
    issue_type: Literal["missing_auth", "idor", "broken_access_control", "auth_bypass", "privilege_escalation"]
    severity: Literal["critical", "high", "medium", "low"]
    explanation: str
    fix_suggestion: str
    pr_number: int
    commit_sha: str
    reviewed_at: datetime
    llm_model: str
    prompt_tokens: int
    completion_tokens: int
```

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
    scan_type TEXT NOT NULL,  -- 'attack_surface' | 'dep_risk' | 'pr_review'
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

-- Auth review findings
CREATE TABLE auth_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id),
    repo_id UUID REFERENCES repos(id),
    pr_number INT NOT NULL,
    commit_sha TEXT NOT NULL,
    route TEXT NOT NULL,
    method TEXT NOT NULL,
    file TEXT NOT NULL,
    line INT,
    issue_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    explanation TEXT NOT NULL,
    fix_suggestion TEXT,
    resolved BOOLEAN DEFAULT FALSE,
    resolved_at TIMESTAMPTZ,
    llm_model TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

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
     body: { "modules": ["attack_surface", "deps", "pr_review"] }

GET  /api/v1/repos/{repo_id}/surface
     → Attack surface findings (paginated)
     query: ?status=live&severity=high

GET  /api/v1/repos/{repo_id}/deps
     → Dependency findings (paginated)
     query: ?reachable=true&sort=risk_score

GET  /api/v1/repos/{repo_id}/auth
     → Auth review findings
     query: ?resolved=false&pr=142

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
3. **Few-shot examples** — include one correct-auth example and one bad-auth example in system prompt
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
class AuthFindingResponse(BaseModel):
    route: str
    file: str
    line: Optional[int]
    issue_type: Literal["missing_auth", "idor", "broken_access_control", "auth_bypass", "privilege_escalation"]
    severity: Literal["critical", "high", "medium", "low"]
    explanation: str
    fix_suggestion: str

def parse_llm_response(raw: str) -> List[AuthFindingResponse]:
    # Strip markdown code fences if present
    cleaned = re.sub(r"```(?:json)?", "", raw).strip()
    data = json.loads(cleaned)
    return [AuthFindingResponse(**item) for item in data]
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
  - `/repos/{owner}/{name}/auth` — Auth review history tab
- `/repos/{owner}/{name}/scans/{id}` — Live scan view (WebSocket)

**Key design decisions:**
- Risk score prominently displayed: **0-100, color-coded** (green/yellow/orange/red)
- Attack surface visualized as a simple host table (not a graph — graphs are unreadable)
- Dep findings sorted by risk score, grouped by "Reachable / Not Reachable"
- Auth findings shown per-PR with link to GitHub PR comment

### CLI (`sentinel`)

```bash
# Install
pip install sentinel-cli

# Authenticate
sentinel auth login   # opens browser → GitHub OAuth

# Commands
sentinel repos list
sentinel scan --repo org/repo [--module attack_surface|deps|pr_review] [--wait]
sentinel report --repo org/repo [--format json|table|markdown] [--output file]
sentinel surface --repo org/repo [--live-only] [--severity high]
sentinel deps --repo org/repo [--reachable-only] [--fix]
sentinel pr --repo org/repo --pr 142

# Demo mode (no auth required, uses sample data)
sentinel demo --repo torvalds/linux  # will obviously find nothing :)
```

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
- Multiple API routes with varied auth patterns
- Been around long enough to accumulate some CVEs

Good public demo candidates (pick one at launch):
- A popular open-source SaaS backend (think: Outline, Plane, Cal.com)
- Select based on: Python or Node backend, has `requirements.txt`/`package.json`, has deployed demo instance, active community

### Demo Script (for Twitter video)

```
1. "Let me run Sentinel on [repo]" — terminal, single command
2. Attack surface comes back: 3 subdomains, 1 dangling CNAME → "this is takeover-able"
3. Dep risk: 2 reachable CVEs highlighted → show the call trace
4. Auth: replay a past PR that shipped a missing-auth route → "Sentinel would have caught this"
5. Dashboard screengrab — everything in one view
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
# GitHub App
GITHUB_APP_ID=
GITHUB_APP_PRIVATE_KEY=   # base64-encoded PEM
GITHUB_WEBHOOK_SECRET=

# Database
DATABASE_URL=postgresql://...
REDIS_URL=redis://...

# External APIs
SHODAN_API_KEY=
ANTHROPIC_API_KEY=

# Optional
SLACK_WEBHOOK_URL=        # for critical CVE notifications
SMTP_URL=                 # for email notifications
```

---

## 19. Future Work

### v2 Features

| Feature | Description |
|---------|-------------|
| **Public Scanner** | Scan any public GitHub repo without install — tweet-scale discovery mode |
| **Org-wide view** | Single dashboard for all repos in a GitHub org, rolled-up risk score |
| **Go / Rust / Java support** | Extend dep analysis to more ecosystems |
| **Secrets detection** | Scan commits for leaked API keys, credentials |
| **SBOM export** | Generate CycloneDX/SPDX SBOM from dep analysis |
| **Jira/Linear integration** | Auto-create tickets for critical findings |
| **Slack App** | `/sentinel scan org/repo` in Slack |
| **Historical tracking** | Risk score over time, "did you get better or worse?" |
| **Active attack surface** | Optional: nmap scan (with explicit user consent) for more complete port data |
| **Full call graph** | Interprocedural reachability for Python (using `pycg`) |
| **Custom rules** | User-defined auth patterns for bespoke middleware |

### v3 Vision ("find 5 vulnerable repos on Twitter")
- Public database of Sentinel scan results for popular open-source repos
- Anonymized findings shared with repo owners via responsible disclosure
- Opt-in public trust score: "This repo has been scanned by Sentinel: risk score 23/100"

---

## Appendix: Key Technology Choices Rationale

| Decision | Choice | Why |
|----------|--------|-----|
| GitHub App vs Actions | App | One-click install, no repo commit needed, better UX |
| OSV.dev vs Snyk | OSV.dev | Free, open, machine-readable, no rate limits on bulk |
| Cache CVEs vs live | Cache (24hr) | Latency: 150 pkgs × 200ms = 30s unacceptable |
| tree-sitter vs regex | tree-sitter | Correct AST parsing, handles edge cases, multi-language |
| Claude vs GPT-4 | Claude (configurable) | Better instruction-following for structured JSON; configurable |
| Subfinder vs Amass | Subfinder | Faster for passive recon; add Amass as optional enhancement |
| Shodan vs active scan | Shodan | Passive, legal, no rate-limit concerns, instant |
| FastAPI vs Django | FastAPI | Async, WebSocket support, Pydantic validation built-in |
| Celery vs asyncio | Celery | Distributed workers, retries, scheduling — production-grade |
