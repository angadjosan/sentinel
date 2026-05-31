This is close. Will do line-by-line and make it perfect. Then will draw architecture diagram (or have claude make it)

# Sentinel — Product Specification

Sentinel is an agent harness for application security. The core product is a set of reasoning agents — each with a defined tool set, memory access pattern, and loop structure — that work together to find, verify, and remediate vulnerabilities. The infrastructure (graph store, findings DB, CLI) exists to make those agents smarter and faster, not the other way around.

---

## Table of Contents

1. [What Sentinel Is](#1-what-sentinel-is)
2. [Agent Framework and Model Provider Abstraction](#2-agent-framework-and-model-provider-abstraction)
3. [Bring Your Own Key (BYOK)](#3-bring-your-own-key-byok)
4. [The Context Graph — Agent Long-Term Memory](#4-the-context-graph--agent-long-term-memory)
5. [The Agent Roster](#5-the-agent-roster)
6. [Orchestration: The LangGraph Scan Pipeline](#6-orchestration-the-langgraph-scan-pipeline)
7. [Agent Deep Dives](#7-agent-deep-dives)
   - 7.1 Graph Enrichment Agent
   - 7.2 SAST Agent
   - 7.3 SCA Reachability Agent
   - 7.4 Secret Scanner Agent
   - 7.5 Triage Agent
   - 7.6 Pentest Agent
   - 7.7 Plan Review Agent
8. [Tool Definitions](#8-tool-definitions)
9. [Finding Schema and Structured Output](#9-finding-schema-and-structured-output)
10. [Context Graph — Full Specification](#10-context-graph--full-specification)
11. [CLI Commands](#11-cli-commands)
12. [Infrastructure (Supporting Layer)](#12-infrastructure-supporting-layer)

---

## 1. What Sentinel Is

Every existing AppSec tool is a matcher: it takes a pattern (a CVE ID, a rule, a regex) and checks whether the code matches it. Sentinel is not a matcher. It is a set of agents that reason about whether a change is exploitable in the context of your specific architecture.

The key capability this unlocks is twofold:
- **Novel vulns**: An agent that knows your middleware chain, data flow, and module roles can notice that a new route skips auth in a way no signature describes.
- **No false positives**: An agent that knows which app code paths actually reach a vulnerable dependency can refuse to flag the 44 out of 47 CVE matches that are unreachable in your call graph.

Both of these capabilities require persistent architectural memory — the context graph — and reasoning agents that can query that memory at scan time.

---

## 2. Agent Framework and Model Provider Abstraction

Sentinel uses **LangGraph** as its agent orchestration framework. LangGraph models the scan pipeline as a directed state graph: each node is an agent or a processing step, edges are transitions, and the pipeline state (the diff, the subgraph contexts, the in-flight findings list) flows through nodes as a typed object. Conditional edges allow branching (e.g., only route a finding to the pentest agent if its severity is high or critical). Parallel edges allow the SAST, SCA, and secret scanner agents to run simultaneously against the same diff.

LangGraph is built on LangChain's model abstraction layer (`BaseChatModel`). Every agent in the harness takes a `BaseChatModel` instance as a constructor argument. This means any provider that LangChain supports is a drop-in: `ChatAnthropic`, `ChatOpenAI`, `ChatGoogleGenerativeAI`, `ChatGroq`, `ChatOllama`, `ChatMistralAI`, `AzureChatOpenAI`, or any provider with an OpenAI-compatible endpoint via `ChatOpenAI(base_url=..., api_key=...)`. The harness does not care which model backs an agent. It only cares that the model can produce structured output (tool calls or JSON mode) — every major provider supports this.

The harness defines each agent's model as a configuration parameter. When a scan runs, the orchestrator instantiates each agent with the model the user has configured. Swapping models does not require any code changes — only a config update.

---

## 3. Bring Your Own Key (BYOK)

Sentinel is BYOK-first. There is no Sentinel-hosted model. You bring your own API key for whichever provider you want, and it is used directly for all agent calls. Sentinel never sees a cost center — you pay your provider directly, you have full visibility into your usage, and you can use any model tier or self-hosted endpoint you want.

**How keys are provided:**

On first use, `sentinel init` asks which model provider you want to use and prompts for your API key. The key is stored in `~/.sentinel/config.toml` (user-level, outside the repo) under a `[models]` section:

```toml
[models]
provider = "anthropic"
model = "claude-opus-4-8"
api_key = "sk-ant-..."

# Optional: use a different (cheaper) model for low-complexity tasks
fast_model = "claude-haiku-4-5-20251001"
fast_api_key = "sk-ant-..."   # can be the same key
```

The CLI reads these at runtime and constructs the appropriate LangChain model instances before handing them to the agent orchestrator. If you want to use a self-hosted endpoint (e.g., vLLM running Llama-3 70B), you set `provider = "openai-compatible"`, `base_url = "http://localhost:8000/v1"`, and `api_key = "none"`. The harness will use `ChatOpenAI` with your custom base URL.

**Two model tiers:**

The harness uses two model slots: `reasoning_model` and `fast_model`. Reasoning-intensive tasks (SAST, SCA reachability, pentest exploitation) use the `reasoning_model`. Cheaper tasks (secret scanning, plan review first pass, semantic enrichment of small files) use the `fast_model`. Both slots are user-configured; they can point to the same model if you want simplicity. If `fast_model` is not set, all tasks use `reasoning_model`.

**No keys leave the client machine.** When Sentinel is run locally, all LLM calls are made directly from the CLI process to your provider. There is no Sentinel backend that proxies model calls. If you run Sentinel in CI, you inject your API key as a CI secret, and CI makes direct provider calls. This is intentional — you should not need to trust a third party with your model API key.

---

## 4. The Context Graph — Agent Long-Term Memory

The context graph is not a database. It is the agent's long-term memory about your codebase's architecture. Every scan agent uses it the same way a human security engineer uses their mental model of the system: to reason about whether a specific change opens an attack path given everything else they know about the architecture.

The graph is a property graph stored in Neo4j. It has two layers:

**Structural layer (deterministic, built from code).** Built by tree-sitter, which parses any language incrementally. This layer captures what the code does: which functions exist, what they call, which routes exist, what middleware guards them, where user input flows. This is a Code Property Graph (CPG) fusing AST, control flow, and data flow.

**Semantic layer (LLM-derived, overlaid on structural).** Built by the Graph Enrichment Agent (Section 7.1). This layer captures what the code means: "this is the JWT authentication middleware," "this handler is the public payment endpoint," "this function sanitizes input before DB writes," "this module manages admin-only operations." The semantic layer is what makes the structural graph useful for security reasoning — a structural graph alone cannot tell you that a route is missing authentication; it can only tell you that a route exists without a GUARDED_BY edge to a node labeled as an auth middleware.

**Memory access pattern.** When any scan agent needs architectural context for a specific function or route, it does not re-read the codebase. It queries the graph for a 2–3-hop neighborhood of the relevant nodes. The result is serialized as structured text and injected into the agent's prompt. This is the retrieval step. The agent's reasoning is the generation step. Together they are the RAG loop that makes contextual security reasoning tractable without loading an entire codebase into context on every call.

The graph is built incrementally: on first use, a full bootstrap pass parses the entire repo. After that, only changed files are re-parsed and re-enriched on each scan. The graph always reflects the architecture of the current main branch, with branch-specific overlays for in-progress work.

Full graph schema is in Section 10.

---

## 5. The Agent Roster

Sentinel has seven agents. Each is a stateful reasoning loop with a specific tool set, a specific system prompt, and a specific place in the orchestration graph.

| Agent | Role | Model tier | Runs |
|---|---|---|---|
| Graph Enrichment Agent | Reads code, writes semantic labels to graph | fast | On bootstrap and after each diff |
| SAST Agent | Finds known and novel vulns in the diff, reasoned against graph | reasoning | Per scan |
| SCA Reachability Agent | Determines whether CVEs in dependencies are actually reachable | reasoning | Per scan |
| Secret Scanner Agent | Detects secrets and high-entropy strings in the diff | fast | Per scan |
| Triage Agent | Aggregates findings from SAST/SCA/Secret, deduplicates, scores severity | fast | Per scan |
| Pentest Agent | Attempts live exploitation in an isolated container | reasoning | Per finding (post-scan) |
| Plan Review Agent | Reviews a written plan for security issues against graph context | reasoning | On demand |

---

## 6. Orchestration: The LangGraph Scan Pipeline

The scan pipeline is a LangGraph `StateGraph`. The pipeline state is a typed object that carries everything needed across nodes:

```
ScanState:
  project_id:           str
  diff_text:            str
  changed_files:        list[ChangedFile]       # file path + new full content
  head_commit:          str
  base_commit:          str
  branch_name:          str | None
  subgraph_contexts:    dict[str, SubgraphContext]  # keyed by node id (function/route)
  raw_findings:         list[RawFinding]         # outputs from SAST/SCA/Secret before triage
  triaged_findings:     list[Finding]            # outputs from Triage Agent
  pentest_results:      list[PentestResult]      # outputs from Pentest Agent runs
  session_id:           str
  model_config:         ModelConfig
```

**Pipeline nodes and edges:**

```
START
  → graph_update_node          # incremental graph update from diff (deterministic, no LLM)
  → subgraph_extraction_node   # query Neo4j for neighborhoods of all touched nodes (no LLM)
  → [sast_node, sca_node, secret_node]  # parallel fan-out (all three agents run simultaneously)
  → triage_node                # fan-in: aggregate, deduplicate, score
  → [pentest_node_1, pentest_node_2, ...]  # parallel fan-out: one per high/critical finding
  → results_node               # aggregate pentest results, update findings DB, return
END
```

The parallel fan-outs use LangGraph's `Send` API: the orchestrator dispatches multiple agent invocations simultaneously and waits for all to complete before advancing to the next node. Each parallel agent invocation gets its own copy of the relevant state slice (the diff, its subgraph contexts) and writes its outputs back into the shared state.

The pentest fan-out uses a conditional edge: only findings with severity `high` or `critical` (as rated by the Triage Agent) are forwarded to pentest nodes. Lower-severity findings are written to the findings DB as open but not auto-pentested.

This graph structure means:
- SAST, SCA, and Secret Scanner always run concurrently — total wall clock is the slowest of the three, not their sum.
- Pentests for multiple findings run concurrently — total wall clock is the slowest single pentest.
- Each node only knows what it needs from the pipeline state — there is no implicit coupling between agents.

---

## 7. Agent Deep Dives

### 7.1 Graph Enrichment Agent

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

### 7.2 SAST Agent

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
  hypotheses_examined:  list[str]           # written analysis of what was checked
  findings:             list[RawFinding]
```

**Model tier.** `reasoning_model`. SAST is the highest-complexity task in the harness — it requires architectural reasoning, multi-hop graph traversal interpretation, and novel vulnerability pattern recognition.

---

### 7.3 SCA Reachability Agent

**Purpose.** Answer the question that no existing SCA tool answers: not "does this dependency have a CVE?" but "does your application ever actually call the vulnerable code path in this dependency?"

**Loop structure.** Single call per dependency-with-CVE, parallelized across all affected dependencies in the diff.

**How it works.** When a dependency change appears in the diff (an entry in `package.json`, `requirements.txt`, `Cargo.toml`, etc.), the agent receives:
- The CVE descriptions for the new/changed dependency version (fetched from the NVD feed the backend polls).
- The DEPENDS_ON and CALLS edges from the graph: which app-level functions import from this dependency, and what functions within the dependency they call.
- The CVE's affected function/method names (parsed from the CVE description and any available GHSA advisory).

The agent's task is to trace the call chain: starting from the dependency's vulnerable function(s), does any path in the graph reach them from user-accessible code? The agent traces this in both directions: from the vulnerable function inward (who calls it?) and from user-accessible routes outward (what dependency functions do they eventually call?). If the two traces intersect, the dependency is reachable and a finding is warranted. If they do not intersect, the dependency is flagged as "CVE present, not reachable" — informational, not a finding.

**Tools available:**
- `query_graph(cypher: str) → list[Node | Edge]` — same as SAST.
- `fetch_cve_detail(cve_id: str) → CVEDetail` — fetches full CVE detail from the NVD API, including affected function names and vulnerable versions.
- `get_dependency_call_sites(package_name: str) → list[CallSite]` — returns all CALLS edges in the graph where the caller is in the app and the callee is in the named package.

**Structured output schema:**
```
SCAAgentOutput:
  dependency:           str
  version:              str
  cves_examined:        list[str]
  reachable_cves:       list[RawFinding]    # CVEs with a confirmed call path
  unreachable_cves:     list[str]           # CVE IDs with no reachable path (suppressed)
  reachability_reasoning: str               # explanation of the call chain analysis
```

**Model tier.** `reasoning_model`. Tracing call chains through a graph and cross-referencing CVE descriptions requires careful multi-step reasoning.

---

### 7.4 Secret Scanner Agent

**Purpose.** Detect secrets and high-entropy strings in the diff.

**Loop structure.** Single call. No tools needed. This agent does not query the graph.

**How it works.** The agent receives only the diff text. It runs a two-pass analysis:

Pass 1 is pattern-based and runs before the LLM call — this is a deterministic pre-filter executed in the harness itself (not by the agent): regex patterns for AWS access keys, GitHub tokens, Stripe keys, Slack tokens, PEM headers, Google API keys, generic `*_KEY`, `*_SECRET`, `*_PASSWORD` assignments. Every match is passed to the agent as a candidate. This pre-filtering reduces the diff the agent needs to reason about to only the suspicious lines.

Pass 2 is the LLM call: the agent receives the candidates from the regex pass plus any string literal in the diff longer than 20 characters (for entropy analysis). For each candidate, it reasons about whether it is actually a secret (vs. a test fixture, a placeholder, a base64-encoded image, a hash output) and assigns a confidence. The agent also reasons about whether a true secret was accidentally removed from the diff (a deleted file with hardcoded credentials still counts as a finding to ensure rotation).

**Structured output schema:**
```
SecretScannerOutput:
  findings:             list[RawFinding]    # type="secret"
  candidates_reviewed:  int
  false_positives_excluded: int
```

**Model tier.** `fast_model`. Secret scanning is primarily pattern-matching with validation; it doesn't require architectural reasoning.

---

### 7.5 Triage Agent

**Purpose.** Fan-in aggregator. Receives raw findings from all three scan agents, deduplicates, resolves conflicts, re-scores severity with cross-agent context, and produces the canonical finding list for this scan session.

**Loop structure.** Single call. No tools needed.

**Inputs:**
- All raw findings from the SAST, SCA, and Secret Scanner agents.
- The existing open findings list for this project (for deduplication against prior scans via fingerprint matching).
- The suppression list for this project (findings with matching fingerprints are dropped here).

**What it does:**
1. **Deduplication.** Two findings from different agents can describe the same vulnerability differently. The Triage Agent identifies overlapping findings (same file path, overlapping line ranges, related vulnerability types) and merges them into one canonical finding, taking the richer description from whichever agent provided more context.
2. **Severity re-scoring.** The Triage Agent has visibility across all agents' outputs. It can escalate severity if multiple agents independently surface the same issue (corroboration increases confidence), or de-escalate if one agent's finding is contradicted by another's reasoning.
3. **Suppression filtering.** For each finding, the harness computes the fingerprint (described in Section 9) and checks it against the suppression store before the Triage Agent even sees it. Suppressed findings never reach the Triage Agent.
4. **Prioritization ordering.** The Triage Agent outputs its findings in priority order: reproduced > novel architectural > injection-class > dependency-reachable > secrets > other. Within each class, critical before high before medium.

**Structured output schema:**
```
TriageOutput:
  findings:             list[Finding]       # deduplicated, scored, ordered
  merge_log:            list[MergeRecord]   # explains every deduplication decision
  dropped_suppressed:   int
```

**Model tier.** `fast_model`. Triage is aggregation and scoring, not deep reasoning.

---

### 7.6 Pentest Agent

**Purpose.** Attempt live exploitation of a finding in an isolated container running a realistic copy of the app. Confirm or refute that the finding is actually exploitable — the final word on whether a finding is a real vulnerability or a false positive.

**Loop structure.** The Pentest Agent is the most complex agent in the harness. It runs a multi-turn agentic loop until it either successfully exploits the target or exhausts its budget. The loop has four phases:

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
  finding_id:           str
  outcome:              "exploited" | "not_reproducible" | "budget_exhausted"
  exploitation_log:     list[ExploitStep]   # each step: tool called, input, output, reasoning
  proof_of_concept:     ProofOfConcept | None   # only if exploited
  defense_analysis:     str | None              # only if not_reproducible
```

```
ProofOfConcept:
  http_method:          str
  http_path:            str
  headers:              dict
  body:                 str | None
  response_status:      int
  response_body:        str
  exploitation_evidence: str     # plain language: what this proves
```

**Model tier.** `reasoning_model`. The pentest loop requires multi-step reasoning under uncertainty, iterative hypothesis refinement, and interpretation of HTTP responses as exploitation evidence.

---

### 7.7 Plan Review Agent

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

## 8. Tool Definitions

All tools are defined as LangChain `BaseTool` subclasses (or `@tool`-decorated functions) and are registered to agents via LangGraph's tool-calling mechanism. The agent framework handles serialization, validation, and retry on tool call failures.

**`query_graph`**
```
Input:
  cypher:   str    — a read-only Cypher query (MATCH/RETURN only; no WRITE/DELETE)
Output:
  list of nodes and edges, each serialized as a property dict with type label
Side effects: none
```

**`get_file_content`**
```
Input:
  file_path:   str    — relative to repo root
  start_line:  int
  end_line:    int
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
  file_path:   str | None   — filter by file; None returns all
  severity:    str | None   — filter by severity
Output:
  list[Finding]
Side effects: none
```

**`fetch_cve_detail`** (SCA Agent only)
```
Input:
  cve_id:   str
Output:
  CVEDetail: {id, description, cvss_score, affected_functions: list[str], affected_versions: str}
Side effects: none (reads from NVD cache, refreshed every 6 hours by background job)
```

**`get_dependency_call_sites`** (SCA Agent only)
```
Input:
  package_name:   str
Output:
  list[CallSite]: {caller_function, caller_file, callee_function, call_line}
Side effects: none
```

**`http_request`** (Pentest Agent only)
```
Input:
  method:    str
  path:      str
  headers:   dict[str, str]
  body:      str | None
Output:
  HTTPResponse: {status: int, headers: dict, body: str, elapsed_ms: int}
Side effects: sends HTTP request to the isolated pentest container
```

**`run_shell`** (Pentest Agent only)
```
Input:
  cmd:   str    — must match allowlist: grep | find | cat | ls | curl localhost:* | ps | env
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
Side effects: inserts into Postgres findings table, computes and stores fingerprint
```

---

## 9. Finding Schema and Structured Output

All agents return findings using the same `RawFinding` schema. The Triage Agent promotes raw findings to canonical `Finding` objects after deduplication and severity scoring.

**RawFinding** (agent output)
```
RawFinding:
  type:                 "sast" | "sca" | "secret"
  severity:             "critical" | "high" | "medium" | "low" | "informational"
  title:                str
  description:          str      — full reasoning, not truncated
  file_path:            str
  line_start:           int
  line_end:             int
  affected_symbol:      str      — function name | route path | class name | "" for file-level
  reachability_path:    str      — explicit trace from user input to vulnerable operation
  cve_id:               str | None
  dependency_name:      str | None
  fix_instructions:     str      — step-by-step remediation
  fix_diff:             str | None  — optional unified diff patch
  confidence:           float    — 0.0–1.0, agent's self-assessed confidence
  source_agent:         str      — which agent produced this finding
```

**Finding** (canonical, stored in DB)
All RawFinding fields plus:
```
  id:                   str (UUID)
  project_id:           str
  scan_session_id:      str
  branch_name:          str | None
  status:               "open" | "suppressed" | "reproduced" | "not_reproducible" | "fixed"
  fingerprint:          str      — SHA-256(file_path + "\0" + type + "\0" + affected_symbol)
  pentest_result:       PentestResult | None
  created_at:           timestamp
  updated_at:           timestamp
```

**Fingerprint algorithm.** The fingerprint is deliberately insensitive to line numbers (code moves) and to the description text (agents may word findings differently across scans). It is sensitive to the vulnerable symbol and the vulnerability type so that a real change in the affected code invalidates the fingerprint and forces re-evaluation.

```
fingerprint = SHA-256(
  normalize_path(file_path)   +  "\0"  +
  vuln_type                   +  "\0"  +
  affected_symbol
)
```

Where `normalize_path` converts backslashes to forward slashes and strips a leading `./`.

---

## 10. Context Graph — Full Specification

### Node Types

All nodes carry: `id` (UUID), `project_id`, `file_path`, `is_new` (bool, set true when first seen in a diff), `last_seen_commit`, `created_at`, `updated_at`.

**Function**
```
name, signature, start_line, end_line, is_async, is_exported,
semantic_label,    # written by Enrichment Agent
security_role      # e.g. "auth check", "input sanitizer", "payment handler"
```

**Route**
```
http_method, path_pattern, handler_function_id,
semantic_label, security_role,
no_auth_guard    # bool: true if this route has no GUARDED_BY edge to an auth middleware
```

**File**
```
language, module_cluster,
semantic_summary   # written by Enrichment Agent
```

**Class**
```
name, base_classes[],
semantic_label
```

**Middleware**
```
name, applies_to,   # "all" | "route_prefix:<prefix>" | "specific"
semantic_label, security_role
```

**Dependency**
```
package_name, version, ecosystem,
known_cves[],         # CVE IDs, populated by background NVD polling
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

## 11. CLI Commands

The CLI is written in Python, uses the LangGraph pipeline directly (not via an HTTP API — the pipeline runs in-process on the user's machine or in CI). There is no Sentinel-operated cloud backend. All LLM calls go directly to the user's model provider.

**`sentinel init`**
Guided setup: project name, model provider selection, API key entry, Neo4j setup (Sentinel-hosted managed instance or self-hosted URI), writes `~/.sentinel/config.toml` and `sentinel.config.toml` in the repo.

**`sentinel source [file-id ...]`**
Runs the scan pipeline (graph update → SAST + SCA + Secret → Triage) against the current diff. Streams agent progress to the terminal. On completion, prints a findings table sorted by severity.

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

## 12. Infrastructure (Supporting Layer)

The infrastructure exists only to serve the agents. It is not the product.

**Local findings DB.** SQLite by default, stored at `~/.sentinel/findings/<project_id>.db`. For teams that want shared findings, an optional Postgres URI can be configured — the same schema, different backend. The `findings`, `scan_sessions`, `suppressions`, and `pentest_runs` tables are defined in Section 9 and the command sections above.

**Neo4j.** The context graph. Default: Sentinel offers a managed Neo4j Aura Free instance per project (enough for repos up to ~100k LOC). Alternative: bring your own Neo4j URI and credentials, stored in `sentinel.config.toml` (self-hosted, local Docker, or your own Aura subscription). The Neo4j connection is direct from the CLI — no proxy.

**Pentest container.** Runs locally via Docker (or Podman). `sentinel pentest` pulls a base image (`sentinel/runner:latest`) that has Node, Python, Ruby, Go, and Java pre-installed. The repo is mounted into the container. The Pentest Agent's `http_request` tool sends requests to `localhost:<port>` where the app is running inside the container. No internet access from the container.

**No Sentinel-operated server required for core functionality.** The design is intentionally serverless from Sentinel's perspective: the LangGraph pipeline runs on the user's machine, LLM calls go directly to the user's provider, the graph lives in the user's Neo4j instance. Sentinel provides tooling, not infrastructure.
