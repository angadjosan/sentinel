# Implementation Progress

Rough estimate: **~25–35% implemented**, skewed toward infrastructure and CLI scaffolding rather than the intelligence layer.

---

## Well-implemented (~70–80%)

- All CLI commands exist (`init`, `source`, `scan`, `list`, `pull`, `plan`, `pentest`, `suppress`, `runs`, `config`) — `cli/src/index.ts:17–245`
- Database layer — models, migrations, graph schema (nodes/edges/findings tables)
- Graph query API — `graph_query.py`, `graph_merge.py`
- Dashboard — findings, runs, graph explorer pages
- Task queue, trace store, source store infrastructure
- RBAC / suppression with approval flow
- SCA feed fetching (basic) — `sca.py`

---

## Partially implemented (~20–40%)

- Graph construction pipeline — `construction.py` (325 lines) exists but framework adapters (Express, FastAPI, Next.js, Django, Rails, Spring) are likely stubs
- Scan logic — `scan.py` (190 lines) has structure but the LLM reasoning layer defaults to `MockLLMProvider` (`agent.py:32`)
- SCA reachability — has a literal `raise NotImplementedError` at `sca.py:44`

---

## Not implemented / vaporware

- Firecracker microVM sandboxing for pentest — `runner.py` is only 51 lines with no sandbox logic
- Fuzzing tier (libFuzzer/LLVM coverage feedback loop)
- Concurrency tier (TSan integration)
- Native extension fuzzer harnesses
- tree-sitter incremental re-parsing (probably batch parses whole files)
- Real semantic enrichment (the LLM agent that labels nodes runs through a mock by default)
- `--with-retry` on `sentinel plan` (CLI flag exists, unclear if backend loops)

---

The skeleton is solid and the data model matches the spec closely. The gap is the actual intelligence — the LLM-powered graph reasoning, real pentest sandboxing, and the fuzzing/sanitizer tiers described in detail in the README.
