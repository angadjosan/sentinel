# Sentinel — Production Handoff Checklist

Three deployment tiers in ascending complexity. Complete each tier before starting the next.

---

## Tier A — Self-hosted, single org
*One company, their own infra, their own LLM keys. The CLI points at their own API URL. Source code never leaves their network. Zero trust problem. **Build this first.***

### A1 — App boots reliably
- [ ] Write a production docker-compose separate from the local dev compose (strong DB credentials, no `SENTINEL_DEV_MODE`, restart policies)
- [ ] Document all required environment variables (`DATABASE_URL`, `SENTINEL_JWT_SECRET`, `ANTHROPIC_API_KEY`, `CORS_ORIGINS`) with a `.env.example`
- [ ] Add healthcheck endpoints to API and worker and wire them into docker `healthcheck:` directives
- [ ] Add TLS docs — explain how to put nginx/caddy in front of the API; provide a sample nginx config

### A2 — CI/CD for this repo
*Do this before any feature work so every fix is automatically tested.*
- [ ] `.github/workflows/ci.yml` — `pytest worker/tests/`, `pytest api/tests/`, `npm test` in `cli/` on every push and PR
- [ ] `.github/workflows/lint.yml` — `ruff` / `mypy` on Python; `eslint` / `tsc` on TypeScript
- [ ] `.github/workflows/build.yml` — build and push Docker images (API, worker) to a container registry on merge to main
- [ ] Configure branch protection on `main` (require CI pass, require review)
- [ ] Add Dependabot for Python and npm dependency updates
- [ ] Add secret scanning in CI (`gitleaks` or GitHub's built-in) to block credential commits

### A3 — Core scan quality
*SAST and secret scanning are already implemented. These items improve their accuracy.*
- [ ] Express adapter — complete middleware chain ordering and auth detection
- [ ] FastAPI adapter — dependency injection resolution
- [ ] Next.js adapter — file-based routing boundary detection
- [ ] Django adapter — URL pattern parsing and class-based view handling
- [ ] Rails adapter — `routes.rb` parsing and `before_action` inference
- [ ] Spring adapter — annotation processing (`@RequestMapping`, `@PreAuthorize`, `@Secured`)
- [ ] Emit a warning when no adapter matches — currently silent degradation gives a false sense of coverage
- [ ] Symbol resolution — tree-sitter produces CSTs, not call graphs; cross-file `CALLS` edges may be incomplete without a real resolution pass
- [ ] Interprocedural taint — current pass is pattern-based; closures, higher-order functions, and async chains are not tracked through

### A4 — CI integration (scanning PRs)
- [ ] CI environment detection — read `GITHUB_REF`, `GITHUB_BASE_REF`, `CI_COMMIT_BRANCH`, etc. to set the correct merge base
- [ ] Branch graph merge — `graph_merge.py` is a stub; implement 3-way merge semantics, conflict resolution, and node/edge upsert so branch scans can be merged back to main

### A5 — SCA pipeline
- [ ] NVD API v2 HTTP client — real calls, retry/backoff, fallback on outage
- [ ] OSV.dev API client
- [ ] Wire advisory data into the `advisory_cache` Postgres table (schema exists; population missing)
- [ ] Implement `sca.py` — currently raises `NotImplementedError`; integrate advisories into scan pipeline
- [ ] Reachability analysis — only surface a CVE if the vulnerable function is reachable in the call graph

### A6 — Developer experience
- [ ] `sentinel doctor` — validate environment (tree-sitter grammars installed, DB reachable, API key valid, Firecracker binary present if enabled)
- [ ] `--dry-run` flag on `sentinel scan` for CI preview without persisting findings
- [ ] Publish CLI to npm (`@sentinel/cli`) with a `prepublish` build step, or provide a clear `npm install -g` install path
- [ ] Remediation plan generation — `pull` command schema exists but LLM call is not implemented
- [ ] `sentinel plan` — NLP extraction of referenced functions and graph subgraph loading are stubs
- [ ] Notification system — `notifications.py` exists but not integrated; wire up email and Slack/Teams webhook

### A7 — Observability
- [ ] Configure a log aggregation sink (Datadog, Loki, ELK) — structlog is wired; no sink is set
- [ ] Wire Prometheus metrics (token spend per run, task queue depth, agent latency, finding counts) — stub exists in `api/src/sentinel_api/main.py`
- [ ] Add timeout handling for long-running agent calls in `agent.py`
- [ ] Add graceful degradation when LLM provider is down (surface error to CLI, return partial results)
- [ ] Enforce per-task CPU/memory resource limits in the worker

### A8 — Documentation
- [ ] Deployment guide — step-by-step from zero to a running self-hosted instance (prerequisites, docker-compose, env vars, CLI install, first scan)
- [ ] Threat model — what Sentinel protects, what it assumes, what it explicitly does not protect (e.g. the LLM API key is trusted)
- [ ] End-to-end test — real git repo → CLI → API → worker → findings returned

---

## Tier B — Hosted, single tenant per deployment
*You provision a dedicated stack per customer (separate Postgres, separate worker fleet). Source is isolated by infrastructure, not just schema. Operationally heavier but the security story is simple: their data never touches another customer's machines.*

### B1 — Customer provisioning
- [ ] Automated provisioning script/workflow — stand up a fresh API + worker + Postgres stack per customer with no manual steps
- [ ] Customer onboarding flow — provision → send credentials → first scan working
- [ ] Offboarding / teardown — delete all customer data and infrastructure cleanly
- [ ] Billing integration — hook provisioning to a payment provider (Stripe, etc.); gate access on active subscription

### B2 — Security at rest
- [ ] Implement envelope encryption in `source_store.py` — currently stubs only
- [ ] Per-customer encryption keys managed by a KMS (AWS KMS, GCP KMS, or Vault)
- [ ] Secret rotation for JWT secrets, DB credentials, and API keys
- [ ] Scrub secrets from stack traces before storing in trace JSONL (`trace_store.py`)

### B3 — Pentest pipeline
*Optional for Tier A (local subprocess is acceptable for self-hosted). Required for Tier B where you own the infra and must enforce isolation.*
- [ ] Firecracker microVM integration — `vm.py` `SandboxExecutor.run()` raises `NotImplementedError`; implement VM create, network config, egress filtering, sanitizer variant booting, artifact collection, teardown
- [ ] Confirmation oracle completion — `oracle.py` missing MSAN, UBSAN, TSan error pattern parsing; behavioral proof validation incomplete
- [ ] Fuzzer harness generation — `fuzzer.py` is stubs; implement LLM-driven C/C++ harness generation, libFuzzer compilation, execution, LLVM coverage data processing

### B4 — Reliability
- [ ] Circuit breakers for LLM provider calls and external APIs (NVD, OSV)
- [ ] Per-customer SLA alerting (scan took too long, worker died, task stuck in queue)
- [ ] Backup and restore runbook for customer databases

### B5 — Data lifecycle
- [ ] Source retention enforcement — `source_store.py` has stubs; `account.source_retention_days` is never acted on
- [ ] Audit log for all source reads and deletions
- [ ] Incremental graph updates — integrate tree-sitter incremental parse API to reduce latency and token spend on large repos (more important when you're paying for compute per customer)

---

## Tier C — Hosted, multi-tenant shared infra
*Everyone shares the same API and worker fleet, isolated by Postgres schema. Cheapest to operate. Hardest to sell to security-conscious buyers. Requires a full security story before any customer should trust it.*

### C1 — Multi-tenant security
- [ ] Integration test proving cross-tenant query isolation holds — per-tenant Postgres schemas exist but there is no test covering the boundary
- [ ] Harden suppression fingerprinting against pre-seeding attacks — current `file + vuln_type` hash is exploitable
- [ ] Audit prompt-injection surface — verify `_assert_no_repo_content_in_system` in `agent.py` covers every code-reading path; add adversarial test cases
- [ ] Rate limiting on all API endpoints (auth especially)
- [ ] Full security audit / pen test of the Sentinel API itself

### C2 — Compliance
- [ ] SOC2 Type II audit
- [ ] GDPR data handling validation (right to erasure, data residency options)
- [ ] Customer-visible data processing agreement (DPA)

### C3 — Scale
- [ ] Worker autoscaling based on task queue depth
- [ ] CVE feed caching with scheduled refresh and fallback on outage (NVD/OSV reliability matters more when you're serving many customers)
- [ ] Load/stress test for task queue under high concurrent scan volume
- [ ] Prometheus alerting at scale (per-tenant metrics, not just aggregate)
