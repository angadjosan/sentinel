# Implementation Progress

**Rough estimate: ~65% implemented.** The scaffolding is present and largely functional. The core intelligence layer — LLM agent loops with real providers, graph bootstrap wired into scans, per-tenant isolation — is the main outstanding work. The estimate has risen substantially from the prior audit: real LLM providers (Anthropic, OpenAI, Ollama), MCP tool definitions, framework adapters, SCA with NVD, the confirmation oracle, and the Firecracker VM infrastructure have all landed since.

---

## What Is Actually Working

### CLI (`cli/`)
All commands wire through to the API: `init`, `source`, `scan`, `list`, `pull`, `plan`, `pentest`, `suppress`, `runs`, `config`, `auth login`. Exit codes (0/1/2) are correct. Git diff extraction, keychain auth, config management, SSE streaming (`runs watch`) all function.

### API (`api/`)
All spec endpoints exist. Auth (JWT + device flow), RBAC, suppression with approval queue, run cancellation, trace access log, Prometheus `/metrics`. SSE streaming replays existing trace then subscribes to new events via Postgres LISTEN. The API surface is largely complete.

### Worker — infrastructure
- Task queue with `SELECT FOR UPDATE SKIP LOCKED` and Postgres NOTIFY wake-up
- Source snapshots stored encrypted (`content_enc`, Fernet-based per-repo keys)
- Trace storage with offloading to `run_traces` when >1 MB, scrubbed before persistence
- Suppression audit table and fingerprint computation
- Graph merge (`graph_merge.py`) — 3-way merge semantics for branch→main
- DB models cover the full spec schema (nodes, edges, graphs, findings, runs, tasks, users, accounts, repos, source_files, suppression_audit, trace_access_log, token_spend_by_component, advisory_cache, device_auth_sessions)
- Source retention lifecycle (`enforce_source_retention_for_account()`)

### Firecracker VM (`vm.py`)
`FirecrackerAPI` protocol with HTTP API via Unix socket. `MicroVMPlan` with boot/healthcheck argv and egress rules. Shell metacharacter rejection (`FORBIDDEN_SHELL_TOKENS`). Network isolation with iptables egress allowlist. `SandboxExecutor` base class and `LocalSubprocessSandboxExecutor` for local testing. Sanitizer config paths (ASAN/MSAN/TSAN).

### Confirmation Oracle (`oracle.py`)
Parses ASAN/MSAN/TSAN/UBSAN error patterns. Extracts and scrubs stack traces. Validates behavioral proof kinds: `data_exfiltrated`, `auth_bypassed`, `command_executed`, `privilege_escalated`. Returns `ConfirmationResult` with `confirmed`, `kind`, `evidence`.

### SCA (`sca.py`, `nvd.py`)
OSV.dev API client working (real data). NVD API client with token-bucket rate limiting (50 req/30s with key, 5 without). Advisory caching. Reachability check via graph `DEPENDS_ON` edges. Parses: `requirements.txt`, `pyproject.toml` (partial), `package.json`, `yarn.lock`, `pnpm-lock.yaml`, `Gemfile.lock`.

### Framework Adapters (`adapters/`)
All six adapters exist as proper `FrameworkAdapter` ABC subclasses with `detect()` and `extract()`:
- `express.py` — Express routes, middleware chain tracking
- `fastapi.py` — FastAPI decorators, `Depends()` auth detection
- `nextjs.py` — file-based routing, middleware.ts detection
- `django.py` — `urls.py` parsing, `@login_required` detection
- `rails.py` — `routes.rb` parsing, `before_action` detection
- `spring.py` — annotation-based routes, Spring Security integration

### LLM Providers (`agent.py`)
Anthropic SDK integrated with async client and tool-use loop. OpenAI SDK integrated with chat completions and tool calling. Ollama adapter via HTTP POST. Channel separation validation (`_assert_no_repo_content_in_system`). Token tracking per component and iteration.

### MCP Tool Definitions (`tools.py`)
All seven tools defined and dispatched: `graph_neighbors`, `graph_paths`, `graph_taint_paths`, `read_file`, `grep_source`, `emit_finding`, `graph_annotate`.

### Graph Query (`graph_query.py`)
`GraphQuery` class with async `neighbors()`, `paths()`, `taint_paths()`. BFS traversal with cycle detection. `serialize_for_prompt()` with relevance cascading (full for `is_new` nodes, collapsed module summaries ≥2 hops out).

### Tree-sitter (`construction.py`)
JavaScript/TypeScript via `tree_sitter_typescript` / `tree_sitter_javascript`. Python via `tree_sitter_python`. Fallback regex for Go, Rust, Java, C/C++, Ruby. Node ID stability via symbol names + file paths.

### Dashboard (`dashboard/src/`)
Pages for findings list, finding detail, runs list, run detail, graph explorer, team. Filtering by status/severity, severity badges, trend charts (recharts), finding table with sort/pagination.

---

## What Is Missing or Wrong

### 1. SAST agent not wired into scan execution (CRITICAL)

`run_sast()` and the SAST agent loop exist in `sast.py` but are never called from `scan.py`'s `execute_source_scan()`. The current scan path still calls `_emit_pattern_findings` — the regex grep fallback. The spec requires:

- `sast_bootstrap()` call to serialize graph context before agent runs
- Agent receives bootstrap + raw diff as starting context
- Agent drives the scan via tool calls (`read_file`, `graph_taint_paths`, `emit_finding`, etc.)
- SAST, SCA, and secret scan run as three parallel async tasks sharing the same bootstrap

The agent loop is built. It is not called.

### 2. Graph bootstrap not injected into scans (CRITICAL)

`graph_query.py` has `serialize_for_prompt()` and the relevance cascade logic. The `sast_bootstrap()` and `sca_bootstrap()` functions that the spec describes (seed node traversal → serialization → injection into agent starting context) do not exist and are never called from `scan.py`. The agent runs blind — no graph context.

### 3. Per-tenant Postgres schema isolation not implemented (CRITICAL)

The spec requires each account to have its own Postgres schema (`tenant_{account_id}`) with `SEARCH_PATH` isolation making cross-tenant reads impossible at the database level. The implementation uses a single shared schema with application-level `WHERE graph.account_id == principal.account_id` filters. A bug in a single query filter exposes all customers' data. For a security product, this is unacceptable.

### 4. No Alembic migrations (CRITICAL)

No `alembic/` directory, no `alembic.ini`, no migration scripts exist. `migrations.py` uses SQLAlchemy `create_all()` / `create_tables()`. Cannot manage production schema changes without downtime or manual intervention. Required before any production deployment.

### 5. Pentest executor is optional, not default

`_pentest_executor()` in the API returns `None` unless `payload.firecracker` is explicitly configured. `_execute_sandbox_plan()` returns `[]` when `executor=None` — the app never boots, nothing is probed. Default `POST /pentest` marks the finding `not_reproducible` without attempting anything. The spec says every pentest job runs inside a Firecracker microVM.

Also missing: rootfs allocation (unpacking Docker layers into ext4), full network interface setup, sanitizer variants wired to Firecracker execution, TSan concurrency tier.

### 6. Pentest agent does not exist

`pentest.py:_payload_candidates` returns hardcoded payload lists (`["' OR '1'='1", ...]`). The spec calls for the agent to load the graph subgraph for the target finding, read handler and sink source, identify entry points, and generate targeted payloads. There is no pentest agent. The static strings are logged to the trace but never sent to anything.

### 7. Coverage-guided fuzzer lacks agent feedback

`fuzzer.py` has an iterative loop with stagnation detection. Missing: LLVM coverage export parsing (`llvm-cov export`), extracting executed branches with ±3 lines of surrounding source, and feeding that back to the agent to direct the next iteration. The fuzzer reruns without agent guidance.

### 8. `sentinel plan` uses regex scan instead of graph-aware analysis

`scan.py:review_plan()` calls `_emit_pattern_findings()` on the plan text — the same regex matching used for source scanning. The spec requires extracting symbol references by name from the plan text, loading their subgraphs, reading relevant source snapshots, and returning the plan annotated with security comments using graph context.

### 9. `sentinel pull` remediation is trivial

`/findings/{id}/pull` returns `[finding.remediation, two canned sentences]`. The spec calls for a remediation agent that reads the finding's graph paths, affected nodes, and source, then produces a concrete fix plan with specific changes.

### 10. Layered graph query resolution not implemented

The spec defines session → branch → main query resolution as `UNION ALL DISTINCT ON (id)` ordered by graph priority. The implementation queries graphs as flat rows. Session and branch graphs exist as rows in the `graphs` table but there is no query-time union. Edge cases with stale/duplicate results are possible.

### 11. Tree-sitter covers only JS/TS/Python with real parsers

Go, Rust, Java, C/C++, Ruby fall back to regex-based function detection. The spec requires `.scm` tree-sitter query files per language for all ten supported languages with incremental re-parse on diff updates. This is low impact for JS/TS/Python repos, medium impact for polyglot backends.

### 12. SCA missing manifest formats

Not parsed: `Pipfile.lock`, `poetry.lock`, `go.mod` / `go.sum`, `Cargo.toml` / `Cargo.lock`, `pom.xml`, `build.gradle`. No transitive dependency resolution from lockfiles.

### 13. Dashboard missing key spec features

- No taint path visualization with react-flow (node color-coded by kind, edge labels showing taint status)
- No blast radius indicator on run detail page
- No live SSE finding cards during an active scan
- No suppression approval queue UI (team page shows users only)
- Graph explorer is a flat table dump, not interactive traversal
- Finding detail page has no confirmed exploit evidence display

### 14. Enrichment validation loop not implemented

The spec requires a re-queue pass: nodes labeled "auth middleware" with no `GUARDED_BY` edges are flagged for re-enrichment. This validation step does not exist. Labels on structurally inconsistent nodes are not corrected.

---

## Overscoped Code (Cut or Move)

1. **Five analytics API endpoints** — `/analytics/token-spend`, `/analytics/finding-trends`, `/analytics/scan-latency`, `/analytics/false-positive-rate`, `/analytics/confirmation-rate` are not in the spec's endpoint list. Token spend belongs in the run record; trend data can come from dashboard queries on existing tables.

2. **`MockLLMProvider` in production `agent.py`** — Test fixture embedded in production code. Should be in `tests/` only. Having it as the default provider silently masks missing LLM configuration.

3. **Dual source execution paths** — `POST /source` runs inline synchronously; `POST /source/enqueue` queues to the worker. One async path with SSE streaming is the spec'd design.

4. **`BuiltinAdvisorySource` with 4 hardcoded CVEs** — Test data that ships in production code. OSV + NVD are the real implementations.

5. **`suppress approve` / `suppress reject` CLI subcommands** — Not in the README design. Approval/rejection is a dashboard operation per spec.

6. **Duplicate run cancel routes** — `POST /runs/{id}/cancel` and `DELETE /runs/{id}` do the same thing. The spec has `DELETE /runs/{id}`.

7. **`CORS allow_origins=["*"]`** — Must be locked down via environment variable before production.

---

## Highest-Impact Next Work

1. **Wire SAST agent into scan** — Replace `_emit_pattern_findings` with the real agent loop: bootstrap serialization → inject into agent context → tool calls (`read_file`, `graph_taint_paths`, `emit_finding`) → findings persisted only with source evidence. This is the core product value and it is not running.

2. **Implement `sast_bootstrap()` / `sca_bootstrap()`** — Traverse seed nodes from diff, serialize subgraph, inject into agent starting context. `serialize_for_prompt()` is already built; just needs to be called.

3. **Alembic migrations** — Zero-downtime schema management. Required before production.

4. **Per-tenant schema isolation** — Alembic migration to create `tenant_{account_id}` schemas, route worker connections via `SEARCH_PATH`. Application-level filters are not sufficient for a security product.

5. **Make Firecracker default in pentest** — Non-optional executor. Wire boot/healthcheck/probe through the actual Firecracker path.

6. **Tree-sitter expansion** — Add real parsers for Go, Rust, Java, C/C++, Ruby. Python is acceptable as-is.
