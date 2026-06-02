# Sentinel — Product Specification

  

Sentinel is a security analysis harness for application code. The core product is a context graph that holds your codebase's architecture, and a set of scan components — some LLM-driven, some deterministic — that use it to find, verify, and remediate vulnerabilities. Not every scan component is an agent. Secret scanning, taint analysis, and CVE lookups are deterministic processes; using an LLM for them is unnecessary complexity. The infrastructure (graph store, findings DB, CLI) exists to make the reasoning components smarter and faster, not the other way around.

  

---

  

## Table of Contents

  

1. [What Sentinel Is](#1-what-sentinel-is)

2. [Agent Framework and Model Provider Abstraction](#2-agent-framework-and-model-provider-abstraction)

3. [Bring Your Own Key (BYOK)](#3-bring-your-own-key-byok)

4. [The Context Graph — Agent Long-Term Memory](#4-the-context-graph--agent-long-term-memory)

5. [Scan Components](#5-scan-components)

6. [Component Deep Dives](#6-component-deep-dives)

- 6.1 Graph Enrichment Agent

- 6.2 SAST Agent

- 6.3 SCA Reachability (deterministic)

- 6.4 Secret Scanner (deterministic)

- 6.5 Triage (deterministic)

- 6.6 Pentest Agent

- 6.7 Plan Review Agent

7. [Tool Definitions](#7-tool-definitions)

8. [Finding Schema and Structured Output](#8-finding-schema-and-structured-output)

9. [Context Graph — Full Specification](#9-context-graph--full-specification)

10. [CLI Commands](#10-cli-commands)

11. [Infrastructure (Supporting Layer)](#11-infrastructure-supporting-layer)

  

---

  

## 1. What Sentinel Is

  

Every existing AppSec tool is a matcher: it takes a pattern (a CVE ID, a rule, a regex) and checks whether the code matches it. Sentinel is not a matcher. It reasons about whether a change is exploitable in the context of your specific architecture.

  

The key capability this unlocks is twofold:

- **Novel vulns**: A reasoning component that knows your middleware chain, data flow, and module roles can notice that a new route skips auth in a way no signature describes.

- **No false positives**: A component that knows which app code paths actually reach a vulnerable dependency can refuse to flag the 44 out of 47 CVE matches that are unreachable in your call graph.

  

Both of these capabilities require persistent architectural memory — the context graph — and reasoning agents that can query that memory at scan time. Everything else (secret scanning, dependency inventory, taint analysis) is deterministic and should stay that way.

  

---

  

## 2. Agent Framework and Model Provider Abstraction

  

LangChain's model abstraction layer (`BaseChatModel`) backs all LLM calls in Sentinel. Every agent takes a `BaseChatModel` instance as a constructor argument. This means any provider that LangChain supports is a drop-in: `ChatAnthropic`, `ChatOpenAI`, `ChatGoogleGenerativeAI`, `ChatGroq`, `ChatOllama`, `ChatMistralAI`, `AzureChatOpenAI`, or any provider with an OpenAI-compatible endpoint via `ChatOpenAI(base_url=..., api_key=...)`. The harness does not care which model backs an agent. It only cares that the model can produce structured output (tool calls or JSON mode) — every major provider supports this.

  

The harness defines each agent's model as a configuration parameter. When a scan runs, the harness instantiates each agent with the model the user has configured. Swapping models does not require any code changes — only a config update.

  

---

  

## 3. Bring Your Own Key (BYOK)

  

Sentinel is BYOK-first. There is no Sentinel-hosted model. You bring your own API key for whichever provider you want, and it is used directly for all agent calls. Sentinel never sees a cost center — you pay your provider directly, you have full visibility into your usage, and you can use any model tier or self-hosted endpoint you want.

  

This approach is MVP-appropriate and could be made more intuitive over time (e.g., guided key setup in a web UI, per-team key management), but the core model is correct: keys should never pass through Sentinel infrastructure.

  

**How keys are provided:**

  

On first use, `sentinel init` asks which model provider you want to use and prompts for your API key. The key is stored in `~/.sentinel/config.toml` (user-level, outside the repo) under a `[models]` section:

  

```toml

[models]

provider = "anthropic"

model = "claude-opus-4-8"

api_key = "sk-ant-..."

  

# Optional: use a different (cheaper) model for low-complexity tasks

fast_model = "claude-haiku-4-5-20251001"

fast_api_key = "sk-ant-..." # can be the same key

```

  

The CLI reads these at runtime and constructs the appropriate LangChain model instances. If you want to use a self-hosted endpoint (e.g., vLLM running Llama-3 70B), you set `provider = "openai-compatible"`, `base_url = "http://localhost:8000/v1"`, and `api_key = "none"`. The harness will use `ChatOpenAI` with your custom base URL.

  

**Two model tiers:**

  

The harness uses two model slots: `reasoning_model` and `fast_model`. Reasoning-intensive tasks (SAST, SCA reachability, pentest exploitation) use the `reasoning_model`. Cheaper tasks (plan review first pass, semantic enrichment of small files) use the `fast_model`. Both slots are user-configured; they can point to the same model if you want simplicity. If `fast_model` is not set, all tasks use `reasoning_model`.

  

**No keys leave the client machine.** When Sentinel is run locally, all LLM calls are made directly from the CLI process to your provider. There is no Sentinel backend that proxies model calls. If you run Sentinel in CI, you inject your API key as a CI secret, and CI makes direct provider calls.

  

---

  

## 4. The Context Graph — Agent Long-Term Memory

  

The context graph is not a database. It is the persistent architectural memory of your codebase. Every scan component uses it the same way a human security engineer uses their mental model of the system: to reason about whether a specific change opens an attack path given everything else they know about the architecture.

  

The graph is a property graph stored in Neo4j. It has two layers:

  

**Structural layer (deterministic, built from code).** Built by tree-sitter, which parses any language incrementally. This layer captures what the code does: which functions exist, what they call, which routes exist, what middleware guards them, where user input flows. This is a Code Property Graph (CPG) fusing AST, control flow, and data flow.

  

**Semantic layer (LLM-derived, overlaid on structural).** Built by the Graph Enrichment Agent (Section 6.1). This layer captures what the code means: "this is the JWT authentication middleware," "this handler is the public payment endpoint," "this function sanitizes input before DB writes," "this module manages admin-only operations." The semantic layer is what makes the structural graph useful for security reasoning — a structural graph alone cannot tell you that a route is missing authentication; it can only tell you that a route exists without a GUARDED_BY edge to a node labeled as an auth middleware.

  

**Memory access pattern.** When any scan agent needs architectural context for a specific function or route, it does not re-read the codebase. It queries the graph for a 2–3-hop neighborhood of the relevant nodes. The result is serialized as structured text and injected into the agent's prompt. This is the retrieval step. The agent's reasoning is the generation step. Together they are the RAG loop that makes contextual security reasoning tractable without loading an entire codebase into context on every call.

  

The graph is built incrementally: on first use, a full bootstrap pass parses the entire repo. After that, only changed files are re-parsed and re-enriched on each scan. The graph always reflects the architecture of the current main branch, with branch-specific overlays for in-progress work.

  

Full graph schema is in Section 9.

  

---

  

## 5. Scan Components

  

A `sentinel scan` runs seven components. Four require LLM reasoning; three are deterministic. The rule: if the task is graph traversal, pattern matching, or rule application, it is deterministic. Only tasks that require understanding code semantics or reasoning about novel attack paths use an agent.

  

| Component | Type | Role | Model tier | Runs |

|---|---|---|---|---|

| Graph Enrichment | Agent | Reads code, writes semantic labels to graph | fast | On bootstrap and after each diff |

| Secret Scanner | Deterministic | Regex + entropy analysis against the diff | — | Per scan |

| SCA Reachability | Deterministic | Graph traversal from CVE-affected functions to user-accessible routes | — | Per scan |

| SAST | Agent | Finds known and novel vulns in the diff, reasoned against graph | reasoning | Per scan |

| Triage | Deterministic | Fingerprint-based dedup, rule-based severity scoring, priority ordering | — | Per scan |

| Pentest | Agent | Attempts live exploitation in an isolated container | reasoning | Per finding (post-scan, high/critical only) |

| Plan Review | Agent | Reviews a written plan for security issues against graph context | reasoning | On demand |

  

**Scan flow.** On each `sentinel scan`:

1. Incremental graph update from the diff (tree-sitter, deterministic).

2. Subgraph extraction: query Neo4j for neighborhoods of all touched nodes (deterministic).

3. Secret Scanner runs against the raw diff (deterministic).

4. SCA Reachability runs graph traversal for any dependency changes (deterministic).

5. SAST agent reasons about the diff + subgraph contexts.

6. Triage deduplicates and scores all findings (deterministic).

7. Pentest runs for each high/critical finding (parallel, one per finding).

  

---

  

## 6. Component Deep Dives

  

### 6.1 Graph Enrichment Agent

  

**Purpose.** Write semantic labels onto structural nodes in the context graph. Transform "this function is called `checkUser` and calls `db.query`" into "this is the authentication check that validates JWT tokens against the user table."

  

**When it runs.** During bootstrap (once per file cluster, in parallel across all clusters) and during incremental updates (once per affected module cluster after a diff is processed). It runs before any scan agents so they have fresh semantic context.

  

**Loop structure.** This agent does not iterate. Each invocation is a single call: it receives a module cluster's structural data and writes semantic labels back to the graph. It is a map operation across file clusters, not a loop.

  

**Inputs per invocation:**

- A module cluster: list of Function, Route, Class, and Middleware nodes for a directory, each with name, signature, structural neighbors (what they call, what calls them, what routes they handle, what middleware guards them), raw source code snippets.

- Existing semantic labels for any neighboring modules (for cross-module coherence — if the caller's module is labeled "payment processing," that context helps label the callee correctly).

  

**System prompt structure:**

The system prompt describes the agent's role as a security-aware code annotator. It is told: (1) it is building a persistent security memory for a codebase, (2) its labels will be used by other agents to reason about whether changes create vulnerabilities, (3) it must be specific and security-oriented (not just "this function handles users" but "this function is the primary authentication gate that all protected routes depend on"), (4) security roles it should identify include: authentication, authorization, input sanitization, output encoding, rate limiting, session management, payment handling, admin operations, user data access, external service calls.

  

**Tool: `write_semantic_labels(node_id, semantic_label, security_role)`**

The agent calls this tool for each node it processes. The tool writes the label to Neo4j. The agent is instructed to call this tool for every node in the cluster before its response ends. The structured output schema enforces that the agent must emit a label for every node ID in the input list before the call is considered complete — if it misses one, the framework retries with a reminder.

  

**Model tier.** `fast_model`. Semantic enrichment is a labeling task, not a deep reasoning task. The fast model is sufficient and keeps bootstrap cost low on large codebases (a 500-file repo might produce 200 clusters; the fast model keeps this affordable).

  

---

  

### 6.2 SAST Agent

  

**Purpose.** Identify vulnerabilities in the diff that are actually reachable and exploitable in this specific codebase, using the context graph as architectural memory. Find both known-pattern vulns (injection, XSS, SSRF, etc.) and novel vulns that require architectural understanding (missing auth on a new route, a new code path that bypasses an existing sanitizer).

  

**Loop structure.** The SAST Agent runs a reasoning loop, not a single call. It has a `plan → inspect → conclude` structure:

  

1. **Plan step.** Given the diff and the serialized subgraph contexts for all touched functions/routes, the agent first produces a written analysis plan: which changed code paths look suspicious, what it wants to verify about each one, which tool calls it intends to make. This step does not produce findings. Its output is a list of hypotheses.

  

2. **Inspect step.** For each hypothesis, the agent calls tools to gather evidence: it queries the graph for deeper context (who calls this function? what middleware does this route have?), asks for the raw source of adjacent functions, checks whether there are existing findings for nearby code. The agent iterates on this step — if tool results reveal new hypotheses, it adds them to the list and continues. Maximum 3 rounds of tool calls per hypothesis.

  

3. **Conclude step.** The agent produces its final findings list. For each finding it must: state which hypothesis it came from, describe the vulnerable code path from user input to the vulnerable operation, explain why the architectural context makes it reachable (not just "this code has a SQL injection pattern" but "this function is called by the `/api/search` route which is publicly accessible according to the graph, and `req.query.q` flows directly into the DB call without passing through any sanitizer node"), assign severity, and write fix instructions.

  

**Inputs:**

- The full diff text, with each hunk labeled by file path and line numbers.

- Serialized subgraph contexts for every function and route in the diff (2–3-hop neighborhoods from Neo4j).

- The list of open findings for this project (so it can avoid re-reporting already-known issues in adjacent code).

  

**System prompt structure:**

The system prompt establishes three non-negotiable rules: (1) every finding must cite a specific reachable path from user-controlled input to the vulnerable operation — hypothetical paths don't count; (2) if the architectural context shows the function is only ever called by internal trusted callers (no user input reaches it), that is a reason to withhold a finding, not suppress it; (3) the agent must explicitly reason about whether novel architectural invariants are broken by the diff — if every sibling route has a GUARDED_BY edge to an auth middleware and this new route does not, that is a finding even if no signature matches it.

  

**Tools available:**

- `query_graph(cypher: str) → list[Node | Edge]` — execute a Cypher query against Neo4j. The agent uses this to explore beyond the pre-fetched 2–3-hop neighborhood when a hypothesis warrants deeper inspection.

- `get_file_content(file_path: str, start_line: int, end_line: int) → str` — read a slice of a source file. Used to inspect adjacent code not in the diff.

- `get_open_findings(file_path: str) → list[Finding]` — fetch existing open findings for a file to avoid duplication.

  

**Structured output schema:**

```

SASTAgentOutput:

hypotheses_examined: list[str] # written analysis of what was checked

findings: list[RawFinding]

```

  

**Model tier.** `reasoning_model`. SAST is the highest-complexity task in the harness — it requires architectural reasoning, multi-hop graph traversal interpretation, and novel vulnerability pattern recognition.

  

---

  

### 6.3 SCA Reachability (deterministic)

  

**Purpose.** Answer the question that no existing SCA tool answers: not "does this dependency have a CVE?" but "does your application ever actually call the vulnerable code path in this dependency?" This is a graph traversal problem, not a reasoning problem.

  

**How it works.** When a dependency change appears in the diff (an entry in `package.json`, `requirements.txt`, `Cargo.toml`, etc.):

  

1. **CVE lookup.** Fetch CVE details from the NVD/GHSA cache for the affected version. GHSA advisories include the specific function/method names that are vulnerable. This is a deterministic API lookup.

  

2. **Call site check.** Query the graph for all CALLS edges where the caller is app code and the callee is in the affected package. This is a single Cypher query.

  

3. **Reachability traversal.** For each call site that touches a vulnerable function, traverse backwards through the call graph to find whether any user-accessible Route node can reach it. This is a graph reachability algorithm (BFS/DFS from the vulnerable function, following CALLS edges in reverse, stopping at Route nodes with no `no_auth_guard` flag). No LLM.

  

4. **Output.** If any path from a user-accessible route reaches a vulnerable function: emit a `RawFinding`. If no path exists: emit an informational "CVE present, not reachable" record. Both outcomes are deterministic given the graph state.

  

**Output schema:**

```

SCAOutput:

dependency: str

version: str

cves_examined: list[str]

reachable_cves: list[RawFinding] # CVEs with a confirmed traversal path

unreachable_cves: list[str] # CVE IDs with no reachable path (suppressed)

call_path: list[str] # the actual traversal path, for display

```

  

---

  

### 6.4 Secret Scanner (deterministic)

  

**Purpose.** Detect secrets and high-entropy strings in the diff. This is a deterministic process — no LLM involved.

  

**How it works.** The scanner runs two passes against the raw diff text:

  

**Pass 1 — Pattern matching.** Regex patterns for known secret formats: AWS access keys, GitHub tokens, Stripe keys, Slack tokens, PEM headers, Google API keys, generic `*_KEY`, `*_SECRET`, `*_PASSWORD` variable assignments. Every match becomes a candidate finding with the matched line, file path, and pattern name.

  

**Pass 2 — Entropy analysis.** For every string literal in the diff longer than 20 characters that was not caught by Pass 1, compute Shannon entropy. Strings above the entropy threshold (empirically tuned per character set: base64 strings above ~4.5 bits/char, hex strings above ~3.5 bits/char) are flagged as candidates.

  

Each candidate is classified as a confirmed finding or a false positive using a rule-based filter: known test fixture patterns (e.g., `example`, `placeholder`, `your_key_here`), base64-encoded images (`data:image/`), hash outputs in log contexts, and known-safe variable names are excluded. No LLM call is made.

  

Deleted lines containing secrets are also flagged — a removed hardcoded credential still needs rotation.

  

**Output schema:**

```

SecretScannerOutput:

findings: list[RawFinding] # type="secret"

candidates_reviewed: int

false_positives_excluded: int

```

  

---

  

### 6.5 Triage (deterministic)

  

**Purpose.** Fan-in aggregator. Receives findings from all scan components, deduplicates, filters suppressions, and produces the canonical prioritized finding list for the session. No LLM — all steps are rule-based.

  

**Inputs:**

- All raw findings from SAST, SCA Reachability, and Secret Scanner.

- The existing open findings list for this project (for deduplication against prior scans via fingerprint matching).

- The suppression list for this project.

  

**What it does:**

1. **Suppression filtering.** Compute the fingerprint for each finding (Section 8) and drop any that match the suppression store. Happens first so suppressed findings don't participate in dedup.

2. **Deduplication.** Group findings by fingerprint. Within a group, merge into one canonical finding: take the highest severity, concatenate descriptions, and note which components flagged it (corroboration from multiple components raises confidence).

3. **Severity adjustment.** Rule: if two or more components independently flag the same symbol for the same vulnerability class, escalate severity by one tier (medium → high, high → critical). No LLM — this is a count-and-compare operation.

4. **Prioritization ordering.** Sort output: reproduced > novel architectural > injection-class > dependency-reachable > secrets > other. Within each class: critical → high → medium → low.

  

**Output schema:**

```

TriageOutput:

findings: list[Finding] # deduplicated, scored, ordered

merge_log: list[MergeRecord] # which findings were merged and why

dropped_suppressed: int

```

  

---

  

### 6.6 Pentest Agent

  

**Purpose.** Attempt live exploitation of a finding in an isolated container running a realistic copy of the app. Confirm or refute that the finding is actually exploitable — the final word on whether a finding is a real vulnerability or a false positive.

  

**Loop structure.** The Pentest Agent is the most complex component in the harness. It runs a multi-turn agentic loop until it either successfully exploits the target or exhausts its budget. The loop has four phases:

  

**Phase 1 — Reconnaissance (1–2 iterations).**

The agent reads the vulnerable function's source code and its callers using `read_file`. It inspects the route that exposes the function using `query_graph`. It traces the input path: which HTTP parameter reaches the vulnerable operation, what transformations it passes through on the way. The agent writes a written exploitation plan at the end of this phase: what vulnerability type, what payload strategy, what HTTP endpoint and parameter to target.

  

**Phase 2 — Initial exploit attempt (1–3 iterations).**

The agent sends its first HTTP request using `http_request`. It examines the response: status code, body, headers, timing. If the exploit succeeded (observable output confirming exploitation — error output leaking stack traces, successful exfiltration, altered app behavior), it moves to the conclude phase. If not, it reasons about why: was the payload format wrong? Is there a sanitization step it didn't account for? Does the response reveal information about the app's internal behavior?

  

**Phase 3 — Refinement (0–5 iterations).**

The agent refines its payload based on Phase 2 observations. It may read additional source files to understand sanitization logic, query the graph for middleware it might have missed, or try alternative payload encodings. Each iteration ends with an HTTP request and a response analysis. The agent is explicitly instructed: if it has not found a successful exploit after 5 refinement iterations, it must conclude and report "not reproducible" with its reasoning.

  

**Phase 4 — Conclude.**

If exploited: the agent writes the successful exploit as a structured proof-of-concept (the exact HTTP request, the observable evidence of exploitation, a plain-language explanation of what was demonstrated). If not reproducible: the agent writes its reasoning (which defenses prevented exploitation, what would need to change for it to be exploitable, whether the finding is a false positive or a deferred risk). The harness updates the finding status accordingly.

  

**Inputs:**

- The full `Finding` object (description, file path, affected function, fix instructions).

- The serialized subgraph context for the affected function and route.

- The app's port number (determined by the app runner boot sequence).

  

**Tools available:**

- `read_file(path: str, start_line: int, end_line: int) → str` — reads source code from the running container.

- `http_request(method: str, path: str, headers: dict, body: str | None) → HTTPResponse` — sends an HTTP request to the running app at `localhost:<port>`. This is the primary exploitation tool.

- `run_shell(cmd: str) → str` — restricted shell inside the container. Allowed commands: `grep`, `find`, `cat`, `ls`, `curl localhost:*`, `ps`, `env`. Cannot modify files. Cannot make outbound network requests. Used to inspect the app's file system state or read config.

- `query_graph(cypher: str) → list[Node | Edge]` — same graph query tool as other agents.

  

**Budget:** Maximum 10 HTTP requests total per pentest run. Maximum 15 tool calls total. Maximum 10 minutes wall clock. If any budget is exceeded, the run concludes with "not reproducible due to budget exhaustion" — this is distinct from "not reproducible due to confirmed defense" and is surfaced differently to the user.

  

**Structured output schema:**

```

PentestResult:

finding_id: str

outcome: "exploited" | "not_reproducible" | "budget_exhausted"

exploitation_log: list[ExploitStep] # each step: tool called, input, output, reasoning

proof_of_concept: ProofOfConcept | None # only if exploited

defense_analysis: str | None # only if not_reproducible

```

  

```

ProofOfConcept:

http_method: str

http_path: str

headers: dict

body: str | None

response_status: int

response_body: str

exploitation_evidence: str # plain language: what this proves

```

  

**Model tier.** `reasoning_model`. The pentest loop requires multi-step reasoning under uncertainty, iterative hypothesis refinement, and interpretation of HTTP responses as exploitation evidence.

  

---

  

### 6.7 Plan Review Agent

  

**Purpose.** Review a written plan (design doc, spec, PR description, architecture decision) for security issues before any code is written. Query the context graph to ground the review in the actual security posture of the existing system.

  

**Loop structure.** Two-pass single invocation:

  

Pass 1 — Context retrieval: The harness extracts noun phrases from the plan text that match node names or semantic labels in the graph (using fuzzy string matching against the semantic labels written by the Graph Enrichment Agent). For each match, it fetches the node's 2-hop neighborhood. This is a deterministic pre-processing step, not an agent call.

  

Pass 2 — Agent call: The Plan Review Agent receives the plan text plus all retrieved subgraph contexts. It produces: (1) a list of security concerns, each grounded in specific graph context (e.g., "the plan proposes adding a new endpoint to the payment module; the graph shows the payment module's routes are guarded by both auth middleware and a CSRF token check — the plan does not mention CSRF handling for the new endpoint"), and (2) an annotated version of the plan text with inline security recommendations marked with a consistent tag.

  

If `--with-retry` is passed, the harness runs the agent again on the annotated plan, repeating until zero concerns are surfaced or 3 passes complete. Each pass's concerns list is shown to the user.

  

**Tools available:**

- `query_graph(cypher: str) → list[Node | Edge]`

- `get_open_findings(filter: dict) → list[Finding]` — surface any existing open findings relevant to the plan's scope.

  

**Model tier.** `reasoning_model`.

  

---

  

## 7. Tool Definitions

  

All tools are defined as LangChain `BaseTool` subclasses (or `@tool`-decorated functions) and are registered to agents via LangChain's tool-calling mechanism. The agent framework handles serialization, validation, and retry on tool call failures.

  

**`query_graph`**

```

Input:

cypher: str — a read-only Cypher query (MATCH/RETURN only; no WRITE/DELETE)

Output:

list of nodes and edges, each serialized as a property dict with type label

Side effects: none

```

  

**`get_file_content`**

```

Input:

file_path: str — relative to repo root

start_line: int

end_line: int

Output:

str — file content slice with line numbers

Side effects: none

```

  

**`write_semantic_labels`** (Enrichment Agent only)

```

Input:

labels: list[{node_id: str, semantic_label: str, security_role: str}]

Output:

{written: int, failed: int}

Side effects: writes to Neo4j

```

  

**`get_open_findings`**

```

Input:

file_path: str | None — filter by file; None returns all

severity: str | None — filter by severity

Output:

list[Finding]

Side effects: none

```

  

**`http_request`** (Pentest Agent only)

```

Input:

method: str

path: str

headers: dict[str, str]

body: str | None

Output:

HTTPResponse: {status: int, headers: dict, body: str, elapsed_ms: int}

Side effects: sends HTTP request to the isolated pentest container

```

  

**`run_shell`** (Pentest Agent only)

```

Input:

cmd: str — must match allowlist: grep | find | cat | ls | curl localhost:* | ps | env

Output:

str — stdout + stderr combined

Side effects: runs read-only command inside pentest container

```

  

**`create_finding`** (called by harness, not agents directly — agents return structured output, harness persists it)

```

Input:

RawFinding object

Output:

{finding_id: str}

Side effects: inserts into findings table, computes and stores fingerprint

```

  

---

  

## 8. Finding Schema and Structured Output

  

All components return findings using the same `RawFinding` schema. The Triage Agent promotes raw findings to canonical `Finding` objects after deduplication and severity scoring.

  

**RawFinding** (component output)

```

RawFinding:

type: "sast" | "sca" | "secret"

severity: "critical" | "high" | "medium" | "low" | "informational"

title: str

description: str — full reasoning, not truncated

file_path: str

line_start: int

line_end: int

affected_symbol: str — function name | route path | class name | "" for file-level

reachability_path: str — explicit trace from user input to vulnerable operation

cve_id: str | None

dependency_name: str | None

fix_instructions: str — step-by-step remediation

fix_diff: str | None — optional unified diff patch

confidence: float — 0.0–1.0, component's self-assessed confidence

source_component: str — which component produced this finding

```

  

**Finding** (canonical, stored in DB)

All RawFinding fields plus:

```

id: str (UUID)

project_id: str

scan_session_id: str

branch_name: str | None

status: "open" | "suppressed" | "reproduced" | "not_reproducible" | "fixed"

fingerprint: str — SHA-256(file_path + "\0" + type + "\0" + affected_symbol)

pentest_result: PentestResult | None

created_at: timestamp

updated_at: timestamp

```

  

**Fingerprint algorithm.** The fingerprint is deliberately insensitive to line numbers (code moves) and to the description text (components may word findings differently across scans). It is sensitive to the vulnerable symbol and the vulnerability type so that a real change in the affected code invalidates the fingerprint and forces re-evaluation.

  

```

fingerprint = SHA-256(

normalize_path(file_path) + "\0" +

vuln_type + "\0" +

affected_symbol

)

```

  

Where `normalize_path` converts backslashes to forward slashes and strips a leading `./`.

  

---

  

## 9. Context Graph — Full Specification

  

### Node Types

  

All nodes carry: `id` (UUID), `project_id`, `file_path`, `is_new` (bool, set true when first seen in a diff), `last_seen_commit`, `created_at`, `updated_at`.

  

**Function**

```

name, signature, start_line, end_line, is_async, is_exported,

semantic_label, # written by Enrichment Agent

security_role # e.g. "auth check", "input sanitizer", "payment handler"

```

  

**Route**

```

http_method, path_pattern, handler_function_id,

semantic_label, security_role,

no_auth_guard # bool: true if this route has no GUARDED_BY edge to an auth middleware

```

  

**File**

```

language, module_cluster,

semantic_summary # written by Enrichment Agent

```

  

**Class**

```

name, base_classes[],

semantic_label

```

  

**Middleware**

```

name, applies_to, # "all" | "route_prefix:<prefix>" | "specific"

semantic_label, security_role

```

  

**Dependency**

```

package_name, version, ecosystem,

known_cves[], # CVE IDs, populated by background NVD polling

last_cve_check_at

```

  

### Edge Types

  

| Edge | From | To | Properties |

|---|---|---|---|

| CALLS | Function | Function | `call_site_line`, `is_conditional` |

| IMPORTS | File | File or Dependency | `import_path` |

| FLOWS_TO | Function | Function | `data_label` (what flows, e.g. "req.body.email") |

| GUARDED_BY | Route or Function | Middleware | `guard_order` (position in chain) |

| DEFINES | File | Function or Class | — |

| HANDLES | Route | Function | — |

| DEPENDS_ON | File | Dependency | `semver_range` |

| EXTENDS | Class | Class | — |

| INSTANTIATES | Function | Class | `instantiation_line` |

  

### Bootstrap Algorithm (First Run)

  

1. **File inventory.** Walk the repo tree, filter to source files by extension, detect language per file.

2. **Tree-sitter structural parse.** For each file: extract Function nodes, Class nodes, Route registrations (framework-specific patterns), Middleware registrations, import statements, function call sites. Write all nodes to Neo4j. Write DEFINES, HANDLES, IMPORTS, CALLS, DEPENDS_ON edges.

3. **Dependency CVE population.** For each Dependency node, query NVD for known CVEs. Write `known_cves` to the node.

4. **Taint analysis pass.** For each route, trace where `req.body`/`req.query`/`req.params` (or framework equivalents) flow through the call graph. Write FLOWS_TO edges wherever tainted data reaches a DB call, shell execution, file write, or external HTTP call.

5. **Middleware chain reconstruction.** For each route, traverse middleware registrations in order and write GUARDED_BY edges with `guard_order`. Mark routes with no auth-middleware guard with `no_auth_guard = true`.

6. **Semantic enrichment.** Cluster files by directory. For each cluster, call the Graph Enrichment Agent. Runs in parallel across clusters, capped at 10 concurrent LLM calls to avoid provider rate limiting.

7. **Mark complete.** Set `graph_bootstrapped = true` in the project config.

  

### Incremental Update (Per Diff)

  

For each file in the diff: re-parse with tree-sitter, compute delta against existing nodes, upsert changed nodes, delete removed nodes and their edges, write new edges. Re-run taint analysis for affected routes (transitively — any route calling a changed function). Re-run Enrichment Agent for touched module clusters.

  

---

  

## 10. CLI Commands

  

The CLI is written in Python and runs the scan pipeline in-process on the user's machine or in CI. There is no Sentinel-operated cloud backend. All LLM calls go directly to the user's model provider.

  

**`sentinel init`**

Guided setup: project name, model provider selection, API key entry, Neo4j setup (Sentinel-hosted managed instance or self-hosted URI), writes `~/.sentinel/config.toml` and `sentinel.config.toml` in the repo.

  

**`sentinel source [file-id ...]`**

Runs the scan pipeline (graph update → Secret Scanner + SAST + SCA → Triage) against the current diff. Streams progress to the terminal. On completion, prints a findings table sorted by severity.

  

**`sentinel pentest <id | description>`**

Boots the app via `sentinel-app-runner.sh`, runs the Pentest Agent against a specific finding. Streams the exploitation log to the terminal in real time.

  

**`sentinel scan [--no-pentest]`**

Runs `sentinel source` and then auto-pentests all high/critical findings in parallel. The default full-cycle command.

  

**`sentinel list [--status ...] [--severity ...] [--branch ...]`**

Reads from the local findings DB (SQLite for local runs; Postgres if a shared project DB is configured). Renders a table.

  

**`sentinel pull <id>`**

Displays a full finding with fix instructions. If `fix_diff` is present, offers to apply it with `git apply`.

  

**`sentinel plan [file | stdin] [--with-retry]`**

Runs the Plan Review Agent against a written plan. Outputs concerns and an annotated plan.

  

**`sentinel suppress <id>`**

Marks a finding suppressed. Writes a suppression record with the fingerprint. Future scans silently skip matching fingerprints.

  

**`sentinel generate app-runner`**

Detects the project's framework and generates a starter `sentinel-app-runner.sh`.

  

**`sentinel ci-setup`**

Prints instructions for adding Sentinel to CI: the environment variable name for the API key, the recommended `sentinel scan` command for the pipeline step, and the default exit code behavior.

  

---

  

## 11. Infrastructure (Supporting Layer)

  

The infrastructure exists only to serve the scan components. It is not the product.

  

**Local findings DB.** SQLite by default, stored at `~/.sentinel/findings/<project_id>.db`. For teams that want shared findings, an optional Postgres URI can be configured — the same schema, different backend. The `findings`, `scan_sessions`, `suppressions`, and `pentest_runs` tables are defined in Section 8 and the command sections above.

  

**Neo4j.** The context graph. Default: Sentinel offers a managed Neo4j Aura Free instance per project (enough for repos up to ~100k LOC). Alternative: bring your own Neo4j URI and credentials, stored in `sentinel.config.toml` (self-hosted, local Docker, or your own Aura subscription). The Neo4j connection is direct from the CLI — no proxy.

  

**Pentest container.** Runs locally via Docker (or Podman). `sentinel pentest` pulls a base image (`sentinel/runner:latest`) that has Node, Python, Ruby, Go, and Java pre-installed. The repo is mounted into the container. The Pentest Agent's `http_request` tool sends requests to `localhost:<port>` where the app is running inside the container. No internet access from the container.

  

**No Sentinel-operated server required for core functionality.** The design is intentionally serverless from Sentinel's perspective: the scan pipeline runs on the user's machine, LLM calls go directly to the user's provider, the graph lives in the user's Neo4j instance. Sentinel provides tooling, not infrastructure.