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

### `sentinel source [file-id ...]`

Scans a diff for vulnerabilities. If no file IDs are given, scans the whole diff.

Findings that have been manually ignored get suppressed via a fingerprint-based suppression store (file + line + vuln type hash) carried forward on the context graph.

**Step 1 — Context graph update (runs first):**
Takes the diff and materializes it as new nodes in the context graph. New nodes are tagged as such so the graph always knows which parts of its architecture are freshly introduced vs. established. This is the only place the context graph is written to — there is no separate build step.

**Step 2 — Scan:**
This is the scan. The agent looks at the raw diff and the updated context graph together and asks: does this change open a new attack path?

Thing to think about here: we need to think in terms of loading up the LLM with fresh context in terms of new CVEs from the OWASP website.

Three scan types run here:
- **SAST:** inspects the diff for known and novel vuln patterns, reasoned against the graph
- **SCA:** traditional software supply chain analysis (CVE matching, dependency vulnerabilities) — plus reachability analysis on the graph to confirm whether the vulnerable code is actually callable from this app
- **Secret scanning:** traditional secret detection

Adds findings to the cloud database with an ID, context, and how to fix.

**Context graph lifecycle:**
- Local run → updates the context graph for the dev session; findings loaded as a dev session.
- CI run → updates an isolated branch context graph in the cloud; findings loaded onto the branch with a CI ID.
- CD → does not re-run `sentinel source`; instead merges the branch context graph into the main graph once the branch lands.

---

### `sentinel pentest <id | description | empty>`

Attempts to actually exploit a vulnerability in a realistic replica of the app.

A per-app `sentinel-app-runner.sh` defines how to boot the environment (editable; also used by CI).

**Procedure (runs in the cloud):**
- Boot the app with production-like secrets and config.
- Load the target vuln from ID or natural language. If empty, do agent-driven endpoint fuzzing with source code access.
- Attempt exploitation. The agent greps source while attacking, enabling targeted exploits over generic payloads.

**Outcomes:**
- Exploitable → status: `reproduced via pentest`. Additional fix detail added.
- Not exploitable → status: `not reproducible`. Suppressed or discarded depending on settings.

---

### `sentinel scan [--no-pentest]`

Wrapper: runs `sentinel source` across the full diff, then `sentinel pentest` on each finding in parallel.

Use `--no-pentest` to skip the exploitation step.

---

### `sentinel list`

Lists all vulnerabilities with their current status.

---

### `sentinel pull <id>`

Pulls the fix for that specific vulnerability id. The agent follows the remediation instructions from the database.

---

### `sentinel plan [file / text content] [--with-retry]`

Reviews a plan (file, IDE plan mode output, or freeform) for security issues.

- Queries the context graph for security concerns.
- Updates the plan with better, more secure practices. With `--with-retry`, reruns automatically to verify the updated plan is clean of security issues

## Context Graph

The context graph is what makes contextual reasoning possible. Instead of re-reading the whole codebase on every scan, the agent pulls a 2–3-hop subgraph around the touched code — who calls this function, what middleware guards this route, does user input flow here — and reasons against that slice. That's what kills false positives and surfaces novel vulns.

### Two layers

**Structural (deterministic, built from code)**

A Code Property Graph (CPG): AST + control flow + data flow fused into one model. Built with [tree-sitter](https://tree-sitter.github.io/), which parses any language incrementally with no dependencies.

- **Nodes:** functions, routes, files, classes, middleware, external dependencies
- **Edges:** `CALLS`, `IMPORTS`, `FLOWS_TO`, `GUARDED_BY`, `DEPENDS_ON`

What we extract for security:
- Route → middleware chain → handler (does every public route pass through auth?)
- Data sources (`req.body`, query params) → where they flow (injection surface)
- Which app code actually calls each dependency (SCA reachability: not "does this CVE match a library?" but "does this app ever reach the vulnerable codepath?")

**Semantic (LLM-derived, layered on top)**

Structural graphs tell you what the code does. Semantic labels tell you what it means.

For each module, an agent reads the code and its structural neighbors and writes labels onto nodes: *"this is the JWT auth middleware," "this handler is the payment endpoint," "this module sanitizes user input before DB writes."*

Each time `sentinel source` updates the graph with a new diff, an agent also writes developer intent onto the affected nodes: *"this commit added a new route that skips the rate limiter every sibling route uses."* This is the layer that catches novel vulns — a structural scan alone wouldn't see that pattern.

### Onboarding

On first use, `sentinel scan` detects an empty graph and runs a full-repo bootstrap before scanning: tree-sitter parses every file (structural pass), then an agent enriches each module with semantic labels (one LLM call per file cluster). This is the only slow run. After that, every update is incremental — only changed files get re-parsed and re-enriched.

### Storage

**Neo4j** — property graph with Cypher. Node properties carry semantic labels and security metadata. Edge types carry the relationship (`CALLS`, `GUARDED_BY`, etc.). Free tier is sufficient for most repos; self-hostable for air-gapped environments.

### Query at scan time

1. Extract the functions and routes touched by the diff.
2. Pull each node's 2–3-hop neighborhood from the graph (callers, callees, middleware chain, data sources).
3. Serialize that subgraph as context into the agent prompt alongside the diff.
4. Agent reasons: is this change reachable and exploitable given the architecture?

The agent never re-reads the full codebase. The graph is the memory.

---

## Database
- All findings stored here with IDs, context, and fix instructions.
- Dashboard for monitoring.
- LLM-queryable.
- Hosts the production context graph. Branch graphs (written by CI) are merged in here on deploy; the graph always reflects the architecture of `main`.

## Evals

Published as: raw model vs. raw model + Sentinel.

1. Can the agent successfully load the app? (Node, Python, etc.)
2. Can the agent surface all true positive vulnerabilities in the environment?
3. Can the agent correctly eliminate false positives — turning them into true negatives — via pentesting?

---

## Long Vision

Sentinel becomes an open prompt: a powerful natural-language interface for querying security state across your entire codebase.


1. A set of open source evals for all cybersecurity things.
2. An RL environment for labs to learn how to use Sentinel.