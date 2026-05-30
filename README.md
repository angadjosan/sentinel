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

Findings that have been manually ignored get suppressed via a fingerprint-based suppression store (file + line + vuln type hash) carried forward on the context graph.

---

## Commands

### `sentinel source [file-id ...]`

Scans a diff for vulnerabilities. If no file IDs are given, scans the whole diff.

- **SAST:** Agent inspects the diff in context of the codebase graph — does the incoming code create vulnerabilities relative to the architecture?
- **SCA:** Sources dependency vulnerabilities from published CVEs; checks software supply chain.
- **Secret scanning**
- **Reachability filter:** Prunes findings via context graph + traditional reachability analysis.

Adds findings to the cloud database with an ID, context, and how to fix.
- Local run → loaded as a dev session
- CI run → loaded onto the branch with a CI ID

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

---

## Architecture

### Database
- All findings stored here with IDs, context, and fix instructions.
- Dashboard for monitoring.
- LLM-queryable.
- Hosts the production view of the context graph.

### Context Graph
- Built incrementally: on every diff in CD, an agent reverse-engineers the session and reasoning from the diff and adds it to the graph.
- To bootstrap from scratch: replay commit by commit.

---

## Evals

Published as: raw model vs. raw model + Sentinel.

1. Can the agent successfully load the app? (Node, Python, etc.)
2. Can the agent surface all true positive vulnerabilities in the environment?
3. Can the agent correctly eliminate false positives — turning them into true negatives — via pentesting?

---

## Long Vision

Sentinel becomes an open prompt: a powerful natural-language interface for querying security state across your entire codebase.
