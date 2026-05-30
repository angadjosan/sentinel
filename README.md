# Problem

1. Everyone can now build applications.
2. Thus, everyone needs application security. 
3. The problem: today's AppSec is signature matching, and so is "raw foundation model + grep."

The entire incumbent stack — SAST, SCA, dependency bots — answers one question: *does this code or dependency match a known-bad pattern (a CVE, a rule, a codesmell)?* That paradigm can only find vulnerabilities that look like vulnerabilities it has already catalogued, and it fails in two directions at once:

a. **Blind to novel vulns (false negatives).** Anything that doesn't match a known CVE or rule is counted as "not a vulnerability" — even when it is one. The business-logic flaws and the vulns unique to *your* architecture are exactly the ones that matter most and exactly the ones signatures can't see. Catching them requires architectural understanding of the whole codebase — knowing, e.g., that a new handler skips the auth middleware every sibling route has. A signature engine (or an agent walking codesmells one by one) has no such context, so it can't.

b. **Low signal (false positives).** Everything that matches a pattern gets flagged whether or not it's reachable or exploitable here — "47 vulnerabilities," 3 of which matter. Security teams drown and stop looking.

Both failures share one fix: **contextual reasoning about exploitability.** Matching (grep, codesmells, CVE feeds) isn't the enemy — it's a cheap prior that tells you *where to look*. It's an input, not the product. The product is the layer that reasons about whether a finding is actually reachable and exploitable in *this* codebase, on *this* diff — killing the false positives signatures over-flag and surfacing the novel vulns no signature describes.

A naked LLM can't do this either: no persistent architectural context (it re-derives the codebase every call and hallucinates), no live CVE data (stale), no way to verify its own hunches (just a noisier matcher). The product is the harness that supplies all three.


2. **Which vulnerable dependencies matter for *this* codebase?** Not CVE count — **reachability**, **transitive exposure**, **patch cadence**, and whether the weakness is **actually exploitable** in your call patterns.
3. **What risky semantics shipped in this PR?** Authorization and access control are the headline, but the same lens applies to injection, unsafe deserialization, secret handling, SSRF-shaped fetches, and other OWASP-style classes when they appear in the diff.

# Solution
1. Open source, free agent harness that integrates with all model providers
2. Maintains a context graph of your codebase. When triggered, does two things:
a. Queries the context graph, makes a list of vulnerabilities from this diff. Also runs traditional AppSec software to check for CVEs and such. This covers the supply chain software case (be especially careful in CI for dependency updates)
b. Any vulnerabilities that do stay, it runs an auto pentest. For each of the attack vectors, the coding agent spins up a dev environment. Because it has knowledge of source code, it can efficiently attack and try to see if your vulnerability will work.
c. It'll auto-suggest diffs to fix the vulnerabilities. It'll also auto-pentest for those.
3. Triggers - you can run it manually whenever you have a new plan for writing code or you already have a diff. Also runs in CI for merged code. 
4. Context graph + infra is on cloud. There's a dashboard that lets you monitor and such
5. Any issue that's been manually ignored in the past gets removed somehow?

Sentinel is a **three-stage** pipeline. Each stage answers a different question about what a motivated attacker could **reach** and **abuse**.

| Stage | What it does | Key output |
|---|---|---|
| 1. Attack surface | **Defender inventory** for a seed domain: passive subdomain discovery, live host and technology hints, **TLS** posture (versions, ciphers, cert validity, SANs), **dangling DNS** and takeover-shaped records, **indexed exposure** (e.g. Shodan) without offensive probing, optional **security header** and **email auth (SPF/DMARC)** signals | Unified list of hosts, ports, TLS/DNS issues, and configuration warnings |
| 2. Dependency risk | **Exploitability-oriented** scoring for **PyPI and npm** (v1), extensible to further ecosystems: OSV-backed CVEs, **reachability** (imports and vulnerable symbols where data exists), **transitive depth**, **patch cadence**, known-exploit weighting — not raw CVE volume | Risk-ranked packages with traces and fix guidance |
| 3. LLM code security | **Semantic PR/diff review**: authZ/authN gaps (missing middleware, IDOR, broken access control), **data-flow** red flags (injection, dangerous sinks), **secrets in diff**, risky crypto/default TLS, SSRF-shaped calls, deserialization — framed as **pre-merge review**, not exploitation | Findings with severity, CWE, evidence span, and remediation hints |

*All three stages share a unified findings format. A normal `sentinel scan` shows triage-friendly output in **both** the terminal and the dashboard; use `--quiet` when you only want files and exit codes (e.g. GitHub Actions).*

TODO: add OWASP vulnerabilities and other CVE databases.

https://www.corridor.dev/
https://www.aikido.dev/

Think like Hyper - token in and token out.