# Problem

1. Everyone can now build software products. Thus, everyone needs application security.
2. The problem: today's AppSec is signature matching, and so is "raw foundation model + grep."

The entire incumbent stack — SAST, SCA, dependency bots — answers one question: *does this code or dependency match a known-bad pattern (a CVE, a rule, a codesmell)?* That paradigm can only find vulnerabilities that look like vulnerabilities it has already catalogued, and it fails in two directions at once:

**a. Blind to novel vulns (false negatives).** Anything that doesn't match a known CVE or rule is counted as "not a vulnerability" — even when it is one. The business-logic flaws and the vulns unique to *your* architecture are exactly the ones that matter most and exactly the ones signatures can't see. Catching them requires architectural understanding of the whole codebase — knowing, e.g., that a new handler skips the auth middleware every sibling route has. A signature engine (or an agent walking codesmells one by one) has no such context, so it can't.

**b. Low signal (false positives).** Everything that matches a pattern gets flagged whether or not it's reachable or exploitable here — "47 vulnerabilities," 3 of which matter. Security teams drown and stop looking. **Which vulnerable dependencies matter for *this* codebase?** Not CVE count — **reachability**, **transitive exposure**, **patch cadence**, and whether the weakness is **actually exploitable** in your call patterns.

Both failures share one fix: **contextual reasoning about exploitability.** Matching (grep, codesmells, CVE feeds) isn't the enemy — it's a cheap prior that tells you *where to look*. It's an input, not the product. The product is the layer that reasons about whether a finding is actually reachable and exploitable in *this* codebase, on *this* diff — killing the false positives signatures over-flag and surfacing the novel vulns no signature describes.

A naked LLM can't do this either: no persistent architectural context (it re-derives the codebase every call and hallucinates), no live CVE data (stale), no way to verify its own hunches (just a noisier matcher). The product is the harness that supplies all three.

---

# Solution

An open source cybersecurity agent harness that integrates with all model providers.

---

## Commands

### `sentinel init`

One-time setup for a repository. Run once by any team member; the cloud graph is shared across the entire team from that point.

- Authenticates with the configured model provider (API key or OAuth) and registers the repo in Sentinel's cloud database.
- Writes `sentinel.config.json` to the repo root — the only file `sentinel init` commits to git (see **Developer Experience**).
- Sends the full codebase to the cloud and runs the graph bootstrap: tree-sitter parses every file (structural pass), then an agent enriches each module with semantic labels (one LLM call per file cluster). This is the only slow run — all subsequent operations are incremental. See **Bootstrap** under Context Management for timing and cost.
- The resulting graph is stored in the cloud. No `sentinel.db` or other local artifacts are created.

CI does not re-run `sentinel init`. Once the cloud graph exists, branch graphs and dev session graphs are created automatically on first use. `sentinel init` is a team setup step, not a pipeline step.

---

### `sentinel source [file-path ...]`

Scans a diff for vulnerabilities. Accepts zero or more file paths (relative to repo root) to scope the scan to a subset of the diff — useful for targeting a single changed module without re-scanning unrelated files. If no paths are given, the full diff is scanned.

Findings that have been manually ignored get suppressed via a fingerprint-based suppression store (file + line + vuln type hash) carried forward on the context graph.

**Step 1 — Context graph update (runs first, in the cloud):**
The diff is sent to Sentinel's cloud worker, which materializes it as new or updated nodes in the branch or dev session graph. tree-sitter re-parses only the changed byte ranges (incremental — O(change), not O(file)), upserts the affected nodes, and marks them `is_new: true`. An agent then writes semantic intent onto the new nodes. This is the only place the context graph is written to — there is no separate build step. See **Context Graph** for the full schema.

**Step 2 — Context loading:**
Extracts the functions and routes touched by the diff. Traverses the graph from those seed nodes — following edges to completion, bounded by edge kind rather than hop count. Serializes the resulting subgraph as structured context into the agent prompt alongside the raw diff. The agent never re-reads the full codebase. See **Context Management** for how this works.

**Step 3 — Scan:**
The agent looks at the raw diff and the serialized subgraph together and asks: does this change open a new attack path?

Three scan types run here:
- **SAST:** inspects the diff for known and novel vuln patterns, reasoned against the graph.
- **SCA:** CVE matching and dependency vulnerability analysis against the NVD/NIST and OSV.dev feeds — plus reachability analysis on the graph to confirm whether the vulnerable code is actually callable from this app. For statically typed languages, reachability is high-confidence. For dynamically typed languages (Python, Ruby, JavaScript), dynamic dispatch and monkey-patching mean reachability is a best-effort signal, not a guarantee — the agent notes this uncertainty explicitly in findings rather than suppressing them.
- **Secret scanning:** entropy analysis and regex pattern matching detect credentials, API keys, and tokens in the diff. Graph-aware: detected secrets are traced through `FLOWS_TO` edges to identify whether they reach logged sinks, external HTTP calls, or persisted storage — distinguishing secrets that are merely present from secrets that are actively exfiltrated. Suppresses known-safe patterns (test fixtures, example values, documentation snippets) via a fingerprint allowlist.

Findings are added to the cloud database with an ID, context, and fix instructions. CVE data is fetched from the NVD/NIST and OSV.dev feeds at scan time and injected into SCA context.

**Context graph lifecycle:**
- Local run → the diff is sent to the cloud, which creates or updates a dev session graph scoped to that developer's working diff. Findings stream back to the CLI and are recorded in the dashboard as `status: session`. Nothing is stored locally.
- CI run → updates an isolated branch graph in the cloud; findings are recorded against the branch with a CI run ID.
- CD → does not re-run `sentinel source`; instead merges the branch graph into the main graph once the branch lands. New/updated nodes are upserted, `CONFIRMED_EXPLOIT` edges are preserved, `is_new` flags are cleared.

---

### `sentinel pentest <id | description | empty>`

Attempts to actually exploit a vulnerability in a realistic replica of the app. Confirmation requires a runtime oracle — agent judgment alone is not sufficient.

**Environment definition (`sentinel.config.json`):**

Instead of an imperative shell script, the app environment is declared in `sentinel.config.json`. Sentinel parses this declaratively — it can read, validate, and reason about the config before executing anything.

```json
{
  "boot": "docker compose up -d",
  "healthcheck": "curl -sf http://localhost:3000/health",
  "env": { "from": ".env.sentinel" },
  "variants": {
    "asan":     { "build": "cmake -DCMAKE_BUILD_TYPE=Asan .",     "requires": "clang" },
    "msan":     { "build": "cmake -DCMAKE_BUILD_TYPE=Msan .",     "requires": "clang" },
    "tsan":     { "build": "cmake -DCMAKE_BUILD_TYPE=Tsan .",     "requires": "clang" },
    "coverage": { "build": "cmake -DCMAKE_BUILD_TYPE=Coverage .", "requires": "clang" }
  }
}
```

Variants are optional for interpreted-language apps. For any target with native code (C/C++, CGo, Python C extensions, Node native addons, JNI, Rust FFI), `asan` is required; the others are strongly recommended.

**Source-aware pentest:**

Before probing, the agent loads the context graph subgraph for the target finding: its node, callers, callees, data sources, and any `GUARDED_BY` or `FLOWS_TO` edges. This gives the agent a structural map of what to attack — which endpoints reach the vulnerable code, what inputs flow into it, what guards (if any) stand between the entry point and the sink. The agent greps source while probing, using the graph as a navigation index rather than reading files blindly.

**Procedure (runs in the cloud):**

1. **Boot** the app with production-like secrets and config (plain build).
2. **Instrument** — if native code is detected, boot a parallel sanitizer-enabled instance (`asan`). Attach a debugger to it. The agent can inject debug logic, add trace points, and inspect heap state directly on this instance.
3. **Load target** — from vuln ID (graph lookup), natural language description, or empty (agent-driven, ranked by attack surface from the graph). If empty, rank entry-point nodes by `is_entry_point=true`, `auth_required=false`, and `FLOWS_TO` depth to sinks.
4. **Exploit attempt** — the agent attacks both the plain and sanitizer builds simultaneously, using the graph's taint paths to generate targeted payloads over generic fuzzing.
5. **Fuzzing tier** (for memory safety and native code) — for each suspicious code location, the agent generates a fuzzer harness targeting that function. Compiled with `asan` + `coverage` and run through libFuzzer. After each round, LLVM coverage data is processed and executed branches with ±3 lines of surrounding source are fed back to the agent to direct the next iteration. Continues until a sanitizer crash confirms the hypothesis or coverage plateaus.
6. **Concurrency tier** — for code with shared mutable state, goroutines, threads, or async patterns, a `tsan` instance is run under concurrent load. The agent drives concurrent requests to trigger scheduling windows that expose races.
7. **Native extension tier** — for apps with Python C API, Node N-API, JNI, CGo, or Rust FFI, the agent generates function-level fuzzer harnesses that bypass the HTTP interface entirely, targeting library internals unreachable through API endpoints.

**Confirmation oracle:**

A finding is confirmed only if one of the following is true — agent judgment alone is not an outcome:
- A sanitizer error fired on a reproducible input (`ASan`, `MSan`, `UBSan`, or `TSan` error with stack trace)
- A deterministic behavioral proof was demonstrated: data exfiltrated, authentication bypassed, command executed, privilege escalated

Every confirmed finding carries the sanitizer stack trace or the behavioral proof as evidence in the database record, and a `CONFIRMED_EXPLOIT` edge is written to the context graph linking the entry point to the finding node.

**Outcomes:**
- Sanitizer crash confirmed → `reproduced via pentest (memory safety)` — sanitizer type, stack trace, triggering input
- TSan race confirmed → `reproduced via pentest (concurrency)` — racing goroutine/thread stacks
- Behavioral exploit confirmed → `reproduced via pentest (logic)` — proof artifact
- Not exploitable → `not reproducible`. Suppressed or discarded depending on settings.
- Fuzzing exhausted, no crash → `not reproducible (fuzz exhausted)` — coverage plateau data

---

### `sentinel scan [--no-pentest]`

Wrapper: runs `sentinel source` across the full diff, then `sentinel pentest` on each finding in parallel.

Use `--no-pentest` to skip the exploitation step.

---

### `sentinel list`

Lists all vulnerabilities with their current status.

---

### `sentinel pull <id>`

Applies the fix for a specific vulnerability ID to the local working tree.

1. **Load finding** — fetches the finding record from the cloud database: vuln type, affected node(s), severity, and the remediation instructions the scanner generated.
2. **Plan the fix** — the agent loads the finding's subgraph (entry point, sink, taint path, and any `GUARDED_BY` context) and drafts a minimal code change that closes the attack path without altering surrounding behavior.
3. **Apply** — edits are written to the local working tree as a clean diff. Nothing is committed automatically; the developer reviews and commits.
4. **Verify (optional)** — with `--run-pentest`, `sentinel pentest` is re-run against the patched code to confirm the finding no longer reproduces before the diff is presented.

If the fix is non-trivial (e.g. an architectural change is required), the agent outputs a remediation plan instead of a code edit, with the specific changes described and the graph paths that need to change.

---

### `sentinel plan [file / text content] [--with-retry]`

Reviews a plan (a file path, piped content, or IDE plan-mode output) for security issues before any code is written. Accepts a file path, freeform text, or stdin.

1. **Context load** — extracts every function, route, and data flow the plan references by name. Loads their subgraphs from the cloud graph, including existing `GUARDED_BY` edges and any prior `CONFIRMED_EXPLOIT` findings on those paths.
2. **Security review** — the agent evaluates the plan against the loaded context: does the proposed change remove a guard? Add an unauthenticated entry point to an existing handler? Introduce a new taint path to an existing sink?
3. **Annotate** — outputs the plan with inline security comments. Issues are rated by severity; each suggestion cites the specific graph paths that motivated it.

With `--with-retry`, the annotated plan is re-submitted automatically until no new issues surface (max 3 passes). Useful as a CI gate or pre-commit hook where a clean result is required, not just a review artifact.

---

### `sentinel runs [list | show <id> | replay <id>]`

Manages session traces.

- `list` — shows all recorded runs (local and CI) with status, finding count, and token spend.
- `show <id>` — streams the full agent trace for a run: every graph query, every prompt, every tool call, every finding. Useful for debugging why something was or wasn't flagged.
- `replay <id>` — re-runs the agent on the exact same diff + graph snapshot as the original run. Deterministic: same diff, same graph state, same model. Used to verify that a model upgrade doesn't regress findings.

All runs are stored as append-only JSONL traces in the cloud database. The trace format is designed to be LLM-queryable: `sentinel runs show <id> | ask "why was the SQL injection in auth.go not flagged?"`.

---

## Developer Experience

### Cloud runs and parallelism

`sentinel source` and `sentinel pentest` are designed to run in CI without configuration beyond `sentinel.config.json` being present. The CLI is stateless — no local graph, no local database. CI runs operate on isolated branch graphs in the cloud; they never touch the main graph until the branch lands.

Parallelism is built-in:
- `sentinel scan` runs all pentest jobs concurrently (one per finding), capped by the cloud runner's concurrency limit.
- `sentinel source` runs SAST, SCA, and secret scanning in parallel — three independent agents over the same diff + graph context.
- Multi-repo setups: each repo has its own cloud graph. Cross-repo SCA reachability is supported when both repos are registered under the same Sentinel account — the cloud database resolves cross-repo `DEPENDS_ON` edges at query time, so a vulnerability in a shared internal library surfaces in every service that reaches the affected function, not just in the library itself.

Cloud run output streams back to the terminal in real time. Runs can be cancelled mid-flight from the CLI (`sentinel runs cancel <id>`) or from the dashboard.

### Model and API configuration

```bash
sentinel config set model claude-opus-4-8      # switch model
sentinel config set provider anthropic          # anthropic | openai | google | local
sentinel config set api-key $ANTHROPIC_API_KEY  # stored in system keychain, not .env
sentinel config show                            # print current config
```

Sentinel integrates with all major providers. Local model support (Ollama) is available for air-gapped environments — accuracy degrades on the semantic labeling pass but structural scanning is unaffected.

### Token efficiency

Token spend is the main operational cost lever. Sentinel minimizes it by:
- **Graph-serialized context:** the agent sees the full relevant subgraph, serialized at ~30–50 tokens per node (including semantic labels and edge annotations) rather than reading raw source files. A complete taint path through 20 nodes costs ~600–1,000 tokens; the equivalent source read — 20 functions averaging 40 lines each at ~10 tokens/line — would cost ~8,000 tokens.
- **Incremental graph updates:** only changed nodes are re-parsed and re-enriched. Unchanged architecture is already in the graph.
- **Scan parallelism:** SAST, SCA, and secret scanning share the same graph context load — it's serialized once per scan, not once per scan type.
- **Suppression carry-forward:** ignored findings are suppressed via fingerprint before the agent sees them — they don't consume prompt tokens on future scans.

Token spend per run is logged in the run trace and surfaced in `sentinel runs list`.

### Session traces and replicability

Every run — local dev session or CI — produces an append-only JSONL trace capturing: diff, graph snapshot, all agent prompts and responses, all tool calls, all findings. Traces are the source of truth for debugging and evals.

The pentest step is reproducible by design: `sentinel.config.json` pins the boot procedure, the graph snapshot is stored with the run, and `sentinel runs replay <id>` re-runs against the exact same state. This means pentest results are auditable — you can prove to a reviewer exactly what exploit the agent demonstrated and under what conditions.

### Replicable pentest runner

The `sentinel.config.json` contract (described under `sentinel pentest`) replaces ad-hoc shell scripts with a structured, versionable declaration. Key properties:

- **Agent-readable:** Sentinel parses the config before executing — it can reason about what build variants are available and choose the right exploit strategy without reading shell code.
- **Validated at init time:** `sentinel init` type-checks the config and warns on missing variants before any pentest is attempted.
- **Committed to the repo:** the config lives next to the code it describes. When the boot procedure changes, the diff is reviewable.
- **Sanitizer variants are optional but structured:** for interpreted languages (Python, Node, Ruby), only `boot` and `healthcheck` are required. For native code, Sentinel detects this automatically and errors if `asan` is missing.

---

## Context Management

The agent never reads the full codebase. It reads the graph.

On every `sentinel source` run, context loading follows this procedure:

**1. Extract touched nodes from the diff**
The diff is parsed to identify which functions, routes, classes, and files were modified. These become the "seed nodes" for context loading.

**2. Traverse the graph by edge kind**
From each seed node, Sentinel traverses the graph to completion — following edges until there's nothing left to follow — bounded by edge kind, not hop count. Cutting traversal at an arbitrary depth would miss sinks, miss guards, miss the thing that matters. `max_hops` exists only as a cycle-protection cap, not as a tuning knob.

What gets loaded varies by scan type:

- **SAST:** follow all `FLOWS_TO` edges to their terminal sinks; pull `GUARDED_BY` edges for every route in the traversal; pull 1-hop `CALLS` context around touched functions for call-site reasoning.
- **SCA:** for each vulnerable dependency node, follow `CALLS` edges inward — does any app code reach the vulnerable function? One pass, stops when it does or exhausts the graph.
- **Pentest attack surface:** full `CALLS` tree from every `is_entry_point=true` node down to the target sink; all `FLOWS_TO` taint paths; all `GUARDED_BY` edges. The agent gets the complete structural picture of what it's attacking.

**3. Serialize for the prompt**
The subgraph is serialized into a compact structured format before being injected into the agent prompt:

```
[ROUTE] POST /api/users  auth_required=false  entry_point=true
  → CALLS  [FUNCTION] createUser           trust_level=untrusted
    → CALLS  [FUNCTION] db.query           is_sink=true  tainted=true
    → CALLS  [FUNCTION] sanitizeInput      trust_level=validated
  → GUARDED_BY  none
  ⚠ NEW (this diff)
```

Graph loads are cheap. The serialized subgraph is dense — ~30–50 tokens per node vs. ~300–800 tokens of raw source per function — and the graph lives in the cloud alongside the scan worker. Loading the full relevant subgraph is the right default; there's no reason to artificially truncate it. See **Graph size and context budgets** below for worst-case analysis.

**4. Grepping as a fallback**
If the agent encounters a symbol not in the graph (e.g. a dynamically constructed call), it can grep the source as a fallback. The graph is built to minimize how often this happens — but the escape hatch exists.

**Graph size and context budgets**

A 100k-line codebase produces roughly 8,000–12,000 nodes and 30,000–80,000 edges. A 1M-line monorepo produces roughly 80,000–150,000 nodes.

In practice, a typical diff (5–20 changed functions) traverses 50–300 nodes — 1,500–15,000 tokens of serialized context. Well within context window limits.

The pathological case is a change to a widely-called utility — a function with 500 direct callers, each with their own callees. A naive traversal could put 3,000–5,000 nodes in scope: at 40 tokens/node, that's 120,000–200,000 tokens. The serializer handles this with a relevance cascade:

1. `is_new=1` nodes (touched by the diff) — always included in full.
2. Direct `CALLS` and `FLOWS_TO` neighbors of new nodes — always included in full.
3. Nodes ≥2 hops from any new node — collapsed to module-level summaries (~5 tokens per module).

The agent can request full traversal on a specific path of interest via tool call if a module summary is insufficient. The soft cap is 80,000 tokens of graph context; above it, everything beyond hop 1 is summarized. Token spend from graph loading is reported per-run in `sentinel runs list`.

**Bootstrap (first run)**
On `sentinel init`, the full codebase is sent to the cloud. tree-sitter parses every file (structural pass). Structural nodes and edges are built deterministically from the parse trees. Then an agent makes one LLM call per file cluster (grouped by module/directory) to write semantic labels — file clusters are typically 5–15 files; a 100k-line codebase produces ~80–120 clusters.

A 100k-line codebase typically bootstraps in 10–20 minutes. LLM cost depends on model: a Haiku-class model suffices for the enrichment pass (labels are short, structural context is concrete) and runs $2–5; a Sonnet-class model runs $8–15. After bootstrap, every update is incremental — only nodes touched by the diff are re-parsed and re-enriched.

**Integration with `sentinel pentest`**
The pentest step is source-aware: before probing, it loads the same subgraph context the scanner used, plus any attack path annotations the scanner wrote. The pentest agent uses the graph as a navigation index — it knows which entry points reach the vulnerable sink, what guards stand in the way, and which code paths to fuzz — rather than discovering this by reading files.

---

## Context Graph

The context graph is what makes contextual reasoning possible. The agent traverses the graph from the touched code — following edges to completion, bounded by edge kind — and reasons against the resulting subgraph. That's what kills false positives and surfaces novel vulns.

### Architecture

The graph is a custom implementation — no external graph database required. It runs on SQLite with a thin Python/TypeScript query layer. This keeps it portable (the same binary runs in the cloud, in CI, and in self-hosted environments), zero-ops (no Neo4j server to manage), and agent-readable (the query API is designed for LLM tool calls, not human Cypher queries).

Structural nodes and edges are built from tree-sitter parse trees. Semantic labels are written by LLM. Security metadata is first-class on every node and edge.

### Schema

**Nodes**

```sql
CREATE TABLE nodes (
  id            TEXT PRIMARY KEY,   -- "fn:auth/middleware.ts:validateJWT"
  kind          TEXT NOT NULL,      -- FUNCTION | ROUTE | FILE | CLASS | MIDDLEWARE | DEPENDENCY | PARAMETER
  name          TEXT NOT NULL,
  file          TEXT,
  line_start    INTEGER,
  line_end      INTEGER,
  language      TEXT,

  -- Security metadata (structural — derived from code)
  trust_level   TEXT,               -- untrusted | validated | trusted | internal
  auth_required INTEGER,            -- 0/1
  privilege     TEXT,               -- admin | user | anonymous | service
  is_entry_point INTEGER,           -- 0/1 — user-facing entry points
  is_sink       INTEGER,            -- 0/1 — dangerous ops: db.query, exec, fs.write, eval

  -- Semantic labels (LLM-written)
  label         TEXT,               -- "JWT auth middleware"
  intent        TEXT,               -- "validates token, sets req.user, rejects on expiry"

  -- Graph metadata
  commit_hash   TEXT,               -- last modified
  is_new        INTEGER             -- 0/1 — added or modified in the latest diff
);
```

**Edges**

```sql
CREATE TABLE edges (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  src         TEXT NOT NULL REFERENCES nodes(id),
  dst         TEXT NOT NULL REFERENCES nodes(id),
  kind        TEXT NOT NULL,        -- CALLS | IMPORTS | FLOWS_TO | GUARDED_BY | DEPENDS_ON | SANITIZED_BY | CONFIRMED_EXPLOIT

  -- Security metadata
  tainted           INTEGER,        -- 0/1 — this data flow carries untrusted input
  sanitized         INTEGER,        -- 0/1 — sanitization occurs on this edge
  dynamic_dispatch  INTEGER         -- 0/1 — edge was inferred statically, not parsed (may miss runtime-resolved calls)
);
```

`CONFIRMED_EXPLOIT` edges are written by `sentinel pentest` when a finding is confirmed — they link the entry point node to the sink node along the actual exploit path.

**Findings** (linking graph nodes to security findings)

```sql
CREATE TABLE findings (
  id          TEXT PRIMARY KEY,
  node_id     TEXT REFERENCES nodes(id),
  vuln_type   TEXT,
  status      TEXT,
  evidence    TEXT,                 -- sanitizer stack trace or behavioral proof
  suppressed  INTEGER,              -- 0/1
  fingerprint TEXT UNIQUE           -- file + line + vuln_type hash for dedup
);
```

### Security metadata design

Security roles and access controls are properties on nodes and edges, not a separate layer. This means every graph query automatically surfaces security context without a join.

Key patterns:
- **Auth gap detection:** query for `ROUTE` nodes where `auth_required=0` and at least one sibling route in the same file has `auth_required=1`. These are candidates for missing auth middleware.
- **Taint tracking:** follow `FLOWS_TO` edges where `tainted=1` from `PARAMETER` nodes with `trust_level=untrusted` to `FUNCTION` nodes with `is_sink=1`. No `SANITIZED_BY` edge in the path = injection candidate.
- **Privilege escalation:** find paths from `privilege=anonymous` entry points to `privilege=admin` functions with no `GUARDED_BY` edge.
- **SCA reachability:** for a vulnerable dependency node, check whether any `CALLS` edge reaches the specific vulnerable function. If not reachable, the CVE doesn't apply here — suppress it.

### Query API

The query layer exposes a small, agent-callable API. All methods are available as MCP tool calls so the agent can invoke them directly during a scan.

```python
# Traverse from a node, following specified edge kinds to completion
# max_hops is a cycle-protection cap, not a tuning knob — omit it to traverse fully
graph.neighbors(node_id, edge_kinds=None, max_hops=None)
# → returns list of (node, edge) pairs

# Find all paths between two nodes
graph.paths(src_id, dst_id, edge_kinds=None, max_hops=None)
# → returns list of node paths

# Taint analysis: all paths from sources to sinks
graph.taint_paths(
  source_kinds=["PARAMETER"],
  source_filter={"trust_level": "untrusted"},
  sink_filter={"is_sink": 1}
)
# → returns taint paths with intermediate nodes

# Upsert a node (used by sentinel source on each diff)
graph.add_node(id, kind, name, file, line_start, **security_props)

# Upsert an edge
graph.add_edge(src, dst, kind, **security_props)

# Write semantic labels (used by LLM enrichment pass)
graph.annotate(node_id, label=None, intent=None, **security_props)

# Serialize a subgraph for injection into an LLM prompt
graph.serialize_for_prompt(node_ids)
# → compact structured text representation (~30–50 tokens/node with semantic labels)

# Mark a finding as confirmed exploit (used by sentinel pentest)
graph.confirm_exploit(entry_node_id, sink_node_id, finding_id, evidence)
# → writes CONFIRMED_EXPLOIT edge + updates finding status
```

### Two layers

**Structural (deterministic, built from code)**

Built with [tree-sitter](https://tree-sitter.github.io/), which parses any language incrementally with no dependencies. On `sentinel source`, tree-sitter receives the old parse tree and the changed byte ranges from the diff — it re-parses only the affected subtrees (O(change), not O(file)).

What we extract for security:
- Route → middleware chain → handler (does every public route pass through auth?)
- Data sources (`req.body`, query params) → where they flow (`FLOWS_TO` edges to sinks)
- Which app code actually calls each dependency (SCA reachability)
- FFI boundaries — where managed code crosses into native code, surfaced as pentest targets

**Semantic (LLM-derived, layered on top)**

Structural graphs tell you what the code does. Semantic labels tell you what it *means*.

For each module, an agent reads the code and its structural neighbors and writes `label` and `intent` onto nodes: *"this is the JWT auth middleware," "this handler is the payment endpoint."*

Each time `sentinel source` updates the graph, an agent also writes developer intent onto new nodes: *"this commit added a new route that skips the rate limiter every sibling route uses."* This is the layer that catches novel vulns — structural scanning alone can't see that pattern.

### Graph Reliability

The graph is authoritative but not infallible. Three sources of imprecision and how they're handled:

**Tree-sitter parsing coverage.** tree-sitter grammars for mainstream languages (TypeScript/JavaScript, Python, Go, Rust, Java, C/C++, Ruby) are mature and production-tested. For less common languages, grammar coverage varies. Parse errors produce orphaned nodes flagged with `parse_error=true` — the agent treats these conservatively, escalating rather than suppressing findings on affected paths.

**Semantic label accuracy.** LLM-written `label` and `intent` fields are best-effort. The enrichment pass validates labels against structural neighbors: a node labeled "auth middleware" with no `GUARDED_BY` edges from any route is flagged for re-enrichment. Any node touched by a diff has its labels re-derived on that run, so stale labels on actively changed code are self-correcting. Labels on dormant code may lag; this is acceptable because dormant code is never in the diff.

**Dynamic dispatch.** For dynamically typed languages (Python, Ruby, JavaScript), call edges derived from static analysis may miss runtime-resolved calls — dynamic method lookup, monkey-patching, `eval()`. The graph marks inferred edges with `dynamic_dispatch=true`. The agent treats these paths as uncertain and notes it in findings. Users can manually assert edges via `graph.add_edge` when the runtime behavior is known.

**Ground truth accumulation.** `CONFIRMED_EXPLOIT` edges provide empirical validation of taint paths the graph predicted. Over time, taint paths that have been flagged repeatedly but never confirmed are candidates for graph correction — surfaced in the dashboard as low-confidence findings.

---

### Integration with `sentinel source`

1. Parse diff → extract changed functions/routes/files
2. tree-sitter incremental re-parse → upsert nodes with `is_new=1`
3. LLM enrichment pass → write `label`, `intent`, updated `trust_level` onto new nodes
4. `graph.neighbors(seed_nodes, edge_kinds=["CALLS", "FLOWS_TO", "GUARDED_BY"])` → full subgraph
5. `graph.serialize_for_prompt(subgraph)` → inject into scan prompt
6. Agent writes findings → `graph.add_node(finding)` + `graph.add_edge(FLOWS_TO)`

### Integration with `sentinel pentest`

1. Load finding → `graph.neighbors(finding.node_id, edge_kinds=["CALLS", "FLOWS_TO", "GUARDED_BY", "DEPENDS_ON"])` → full attack surface map
2. `graph.taint_paths(...)` → candidate exploit paths
3. Serialize attack surface as pentest context
4. Agent attacks; on confirmation → `graph.confirm_exploit(entry, sink, finding_id, evidence)`
5. `CONFIRMED_EXPLOIT` edges accumulate over time — they become training signal for which graph patterns are actually exploitable

### Storage

**What lives in git:**
- `sentinel.config.json` — the declarative environment spec (boot procedure, healthcheck, sanitizer variants). Versioned with the code it describes; diffs are reviewable.
- Nothing else. No `sentinel.db`. No graph artifacts.

**What lives in Sentinel's cloud:**
- The context graph, with git-like versioning semantics: a main graph (always reflects `main`), per-branch graphs (one per open branch, isolated until the branch lands), and dev session graphs (per-developer ephemeral overlays, scoped to the current working diff).
- All findings, run traces, and confirmed exploit evidence.

The cloud graph is the source of truth. The CLI is stateless — it sends diffs, receives findings, and stores nothing locally. On `sentinel source`, the diff is sent to the cloud worker; the relevant graph (branch or dev session) is updated there; findings stream back to the terminal. On deploy, the branch graph is merged into the main graph: new/updated nodes are upserted, `CONFIRMED_EXPLOIT` edges are preserved, `is_new` flags are cleared.

Dev session graphs are ephemeral: they exist while a developer is actively working on a diff and are promoted to the branch graph when the same diff runs in CI. They appear in the dashboard as `status: session` until promoted.

**Self-hosted:** for air-gapped environments, the full system can be self-hosted. The cloud worker (graph update, scan, pentest runner) ships as a Docker image; the graph is stored in SQLite behind the worker API. The CLI points at the self-hosted endpoint via `sentinel config set endpoint <url>`. The self-hosted database is a single SQLite file — portable and zero-ops.

---

## Database
- All findings stored here with IDs, context, and fix instructions.
- Dashboard for monitoring.
- LLM-queryable.
- Hosts the production context graph. Branch graphs (written by CI) are merged in here on deploy; the graph always reflects the architecture of `main`.

---

## Evals

Published as: raw model vs. raw model + Sentinel.

1. Can the agent successfully load the app? (Node, Python, C/C++, Go, etc.)
2. Can the agent surface all true positive vulnerabilities in the environment?
   - Web/logic vulns: OWASP Top 10, auth bypass, injection, SSRF
   - Memory safety vulns: heap overflow, use-after-free, uninitialized read, integer overflow → corruption
   - Concurrency vulns: data races, lock-order violations
3. Can the agent correctly eliminate false positives — turning them into true negatives — via pentesting?
4. Does the sanitizer oracle fire on all confirmed memory safety findings? (Zero confirmed memory safety findings without a sanitizer stack trace is a passing grade; any confirmed finding without one is a failing grade.)
5. Coverage: what fraction of crash-triggering inputs were found by the fuzzing tier vs. required manual harness authoring?

---

## Long Vision

Sentinel becomes an open prompt: a powerful natural-language interface for querying security state across your entire codebase.

1. A set of open source evals for all cybersecurity things.
2. An RL environment for labs to learn how to use Sentinel.
