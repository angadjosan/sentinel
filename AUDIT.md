# Sentinel — Architecture Audit & Implementation Plan

**Date:** July 7, 2026 (implemented & reconciled July 8, 2026)  
**Status:** ✅ **Resolved** — all five workstreams (W1–W5) landed and were reconciled into one tree; §5 Gates 0–4 pass. See **§11 Resolution** for what was verified (incl. a real-socket live E2E smoke) and what remains deferred (§7 backlog).  
**Audience:** You + subagents implementing in parallel

---

## How to use this document

1. **Read §1–§3** once — they lock the target architecture and product decisions every task must obey.
2. **Read §6 “Three clocks”** — when to **start**, **merge**, and run **integration smoke**. All five workstreams **start in parallel**; gates (§5) apply at integration, not at kickoff.
3. **Hand off §6 subagent workstreams** — **5 tasks (`W1`–`W5`)**. Copy one prompt block into a new agent session on **day 1**.
4. **Verify with §5 acceptance gates** after merging — not before starting individual streams.
5. The audit findings are in **§2**; phases in **§4**; handoff in **§6**.

### How many “paths”?

| Kind | Count | Meaning |
|------|-------|---------|
| **Architecture paths** | **3** | Competing designs still in the repo (see §2). You’re collapsing these into **1** target. |
| **Implementation workstreams** | **5** | Subagent handoff packages (`W1`–`W5`). |
| ~~SA-00 … SA-20~~ | ~~21~~ | **Retired** — was a fine-grained breakdown of the same 5 streams; use `W1`–`W5` instead. |

### Three clocks (start ≠ merge ≠ done)

This is the most common source of confusion. **Parallel work does not mean “everything works end-to-end on day 1.”** It means five agents can code simultaneously on separate branches.

| Clock | Question it answers | When | W1–W5 |
|-------|---------------------|------|-------|
| **① Start** | Can I begin coding? | **Day 1 — all five** | ✅ Launch every workstream immediately on its own branch |
| **② Merge** | Can this PR land on `main`? | When **your** stream’s tests pass on **your** branch | Each stream merges independently; see merge order below |
| **③ Integration** | Does the **product** work E2E? | **Once** after streams are combined | Run Gates 0–4 (§5) — e.g. `sentinel source` → `sentinel pentest` → dashboard |

**Analogy:** five contractors renovate different rooms the same week (① start). Each finishes their room and gets sign-off (② merge). You only host the housewarming when **all** rooms are done (③ integration).

**What is *not* blocked on day 1**

- W2 can implement `enqueuePentest` + poll before W1’s worker runs — CLI will error on pentest until W1 merges; that’s expected mid-flight.
- W4 can write pentest E2E tests first (TDD) — mark `@pytest.mark.xfail` until W1 lands.
- W5 can build dashboard forms against §3 D1 field names — no need to wait for W2.
- W3 can delete webhook diff storage without waiting for W2 — **except** “delete local pentest” belongs to W2, not W3.

**What *is* blocked until integration (③)**

- Full manual smoke: `sentinel pentest` succeeding end-to-end (needs W1 + W2).
- Gate 0 alone can pass after W1 merges; Gate 1 needs W1 + W2; Gates 2–4 need the relevant streams merged.

**Suggested merge order** (reduces git conflicts, not start order):

`W1 → W4 → W2 → W3 → W5` → run integration smoke (Gates 0–4)

### Subagent invocation template

```text
You are implementing Sentinel workstream WN from AUDIT.md.

Read §1 (target architecture), §3 (locked decisions), and §6 "Three clocks" first.
Implement only WN on branch feat/wN-.... Start immediately — do not wait for other streams.
Respect file ownership in §6 (don't edit other streams' owned paths).
Run the tests listed in WN before opening your PR.
Your PR can merge before integration smoke; E2E may be incomplete until other streams land.
If you need a schema/API shape, use §3 D1 — do not invent conflicting fields.
```

---

## §1 Target architecture (authoritative)

| Layer | Owns | Never owns |
|-------|------|------------|
| **CLI** (Node + local Python engine) | Auth to cloud; git diff; local `read_file` / `grep_source`; **local LLM SAST**; `init` / `source` / `scan` / `plan`; push graph delta + findings | Pentest execution; storing canonical graph/findings locally; sending source/diffs to cloud |
| **Cloud** (API + Postgres + Worker + Dashboard) | Canonical **graph**; canonical **findings**; **pentest** orchestration + execution + runs + confirmation; team dashboard | SAST over customer source; receiving diffs from CLI scan path |

### Data flow (happy path)

```
Developer machine                          Cloud
─────────────────                          ─────
sentinel auth login ─────────────────────► session/JWT
sentinel init / source / scan / plan
  └─ local_cli.py (subprocess)
       • reads repo from disk
       • LLM SAST (local keychain)
       • optional GET /graph/subgraph
  └─ POST /graph/upsert ─────────────────► graph nodes/edges
  └─ POST /findings/ingest ───────────────► findings

sentinel pentest [id]
  └─ POST /pentest ───────────────────────► enqueue kind=pentest
  └─ sentinel runs watch ───────────────► worker executes pentest
                                            updates finding.confirmed
Dashboard / sentinel list / pull ◄──────── findings + runs + graph
```

### Invariants (non-negotiable)

1. **SAST privacy:** Source code and unified diffs never leave the CLI machine on the scan/init/plan path.
2. **Graph on cloud:** Pointers + short semantic labels only (`POST /graph/upsert`).
3. **Findings on cloud:** Metadata via `POST /findings/ingest`; fingerprint dedup.
4. **Pentest on cloud:** Worker owns `kind=pentest`; CLI triggers and polls only.
5. **Runtime oracle:** `confirmed=true` only with sanitizer output or deterministic HTTP/behavioral proof — **not** LLM self-assertion alone.

---

## §2 Audit summary (current vs target)

Scores below are the **original** audit (July 7). The **Now** column is the reconciled state (July 8, all gates passing).

| Area | Then | Now | Headline |
|------|------|-----|----------|
| CLI local SAST | ~80% | ✅ | Unchanged target path; SQLi ground-truth fixture test added (W4) |
| Cloud graph | ~85% | ✅ | Works (node PK composite-key hardening still §7 backlog) |
| Cloud findings | ~90% | ✅ | Works |
| Cloud pentest | ~15% | ✅ | Worker executes `kind=pentest`; HTTP dispatch + hardened oracle; confirmed on target's own response, verified live over real sockets (§11) |
| Docs / tests / UX | ~40% | ✅ | One architecture; dashboard + README tell the truth; no fake-green tests |

**Root cause:** PR #13 local-first refactor moved pentest to CLI while cloud enqueue path rotted. Legacy cloud-worker SAST + GitHub webhook diff storage still exists.

**Three forks in the repo today:**

| Fork | Files |
|------|-------|
| ✅ Target CLI SAST | `worker/sentinel_worker/local_engine.py`, `local_cli.py`, `cli/src/engine/localEngine.ts` |
| ❌ Wrong local pentest | `local_engine.run_local_pentest`, `local_cli pentest`, `cli/index.ts` `runLocalPentest`, `POST /findings/{id}/confirm` |
| ⚠️ Target cloud pentest (unwired) | `POST /pentest`, `pentest.run_pentest`, `worker_main.py`, `runner.py` |
| 🗑️ Legacy cloud scan | `execute_source_scan` + `store_source_snapshot`, GitHub webhook, `source_store.py` |

---

## §3 Locked product decisions

These are **decided for this plan**. Subagents must not re-litigate unless you explicitly change §3.

### D1 — Pentest reachability: dual mode

Support **both** patterns; repo config selects mode:

| Mode | Config | Worker behavior |
|------|--------|-----------------|
| **`staging`** (default for hosted cloud) | `staging_base_url`, `healthcheck_path` on **Repo** | HTTP probe payloads via httpx; no boot argv |
| **`local_worker`** (self-hosted) | `boot`, `healthcheck`, `egress_allowlist` on **Repo** | Subprocess sandbox on worker host (Pattern B) |

Hosted Vercel/Railway workers use **`staging`** only. Self-hosted `docker compose` customers use **`local_worker`**.

### D2 — Pentest LLM credentials

- **SAST:** Local key only (keychain / env). Never stored on server. **Unchanged.**
- **Pentest agent (cloud worker):** Server-side credential via **`SENTINEL_PENTEST_LLM_API_KEY`** env on worker **or** optional encrypted `Account.pentest_api_key` set through dashboard (admin-only). Separate from SAST policy.

### D3 — Pentest source context

**Phase 1:** HTTP-only + cloud graph context + finding metadata. **No** source upload for pentest.

Cloud pentest agent uses graph serialization + vuln_type templates. `read_file` on worker returns 404 unless mode=`local_worker` and repo mount exists (future). Do not block Phase 1 on source snapshots.

### D4 — CLI pentest = enqueue + poll

Remove local pentest execution from product path. `sentinel pentest` → `POST /pentest` → `sentinel runs watch` until terminal.

### D5 — Legacy cloud SAST removal

Remove GitHub webhook cloud diff scan and dead task kinds (`source`, `plan`, `init`) from product path after pentest works. CI uses `action.yml` / `standalone.py` for PR SAST + ingest.

### D6 — Confirm endpoint

Worker writes finding confirmation directly in `run_pentest`. Deprecate public `POST /findings/{id}/confirm` for CLI (keep internal helper or admin-only during migration).

---

## §4 Implementation phases

### Phase 0 — Foundation (blocking everything)

| ID | Work | Output |
|----|------|--------|
| P0.1 | Repo pentest config schema + API | `Repo.staging_base_url`, `pentest_mode`, migration |
| P0.2 | Worker pentest handler in `runner.py` | Tasks `kind=pentest` execute |
| P0.3 | HTTP payload dispatch | Payloads actually hit staging URL |
| P0.4 | Oracle hardening | Agent-only confirm rejected |

**Gate 0:** `POST /pentest` → worker → finding status updates in DB with mocked HTTP server test.

### Phase 1 — CLI + cloud integration

| ID | Work | Output |
|----|------|--------|
| P1.1 | CLI client `pentest()` + poll | `sentinel pentest` cloud-only |
| P1.2 | Remove local pentest path | Delete `run_local_pentest` from CLI flow |
| P1.3 | `scan --pentest` enqueues cloud tasks | No silent skip |
| P1.4 | Sync pentest config CLI → cloud | `sentinel config set staging_base_url` etc. |

**Gate 1:** Manual E2E: `sentinel source` → `sentinel pentest <id>` → dashboard shows cloud run + result.

### Phase 2 — Legacy removal + hygiene

| ID | Work | Output |
|----|------|--------|
| P2.1 | Remove webhook cloud diff scan | Privacy invariant restored |
| P2.2 | Remove dead runner kinds / routes | `repos.py` plan route fixed or deleted |
| P2.3 | Narrow `source_store` | Remove from CLI scan path traces; document pentest-only or delete |
| P2.4 | Dead code cleanup | Schemas, unused UI, ensure.ts docker worker |

**Gate 2:** No code path stores diffs in `tasks.payload` or uploads source on CLI scan.

### Phase 3 — Tests realignment

| ID | Work | Output |
|----|------|--------|
| P3.1 | Pentest worker integration test | Real handler, mock HTTP app |
| P3.2 | Fix misleading API pentest tests | Names match behavior |
| P3.3 | Restore SQLi fixture test | Ground-truth SAST oracle |
| P3.4 | Remove/quarantine `_PatternLLM` for non-webhook tests | |

**Gate 3:** CI catches missing pentest handler regression.

### Phase 4 — UX, docs, polish

| ID | Work | Output |
|----|------|--------|
| P4.1 | `sentinel doctor` | Pre-flight checks |
| P4.2 | Dashboard pentest UX | Runs, config, honest labels |
| P4.3 | README rewrite | Target architecture documented |
| P4.4 | Suppression reason prompt | Dashboard parity with CLI |

### Phase 5 — Scale (parallel, post-MVP)

| ID | Work |
|----|------|
| P5.1 | Node ID composite key migration |
| P5.2 | GitHub App → CI ingest notification only |
| P5.3 | LLM remediation in `pull` |
| P5.4 | Framework adapter warnings surfaced to user |
| P5.5 | Graph branch merge (real 3-way) |

---

## §5 Phase acceptance gates (integration checklist)

Run these **after merging** workstreams — not before starting them. Individual streams may satisfy subsets on their branch (noted per gate).

### Gate 0 — Cloud pentest executes *(needs W1 merged)*

- [x] `runner.py` handles `kind=pentest` without raising
- [x] Worker test: enqueue → claim → complete updates finding
- [x] HTTP payloads sent to configurable base URL (test server)
- [x] Oracle rejects `behavioral_proof` without HTTP/sanitizer evidence
- [x] Pentest run row exists with `kind=pentest` and trace in Postgres

### Gate 1 — CLI integrated *(needs W1 + W2 merged)*

- [x] `sentinel pentest <id>` never spawns local pentest subprocess
- [x] CLI polls until run terminal; prints confirmed/not_reproducible
- [x] `scan --pentest` enqueues one cloud pentest per ingested finding ID
- [x] Repo pentest config readable from cloud API

### Gate 2 — Legacy removed *(needs W3 merged)*

- [x] GitHub webhook does not store diff in task payload
- [x] `POST /repos/{id}/plan` deleted or fixed; no `NameError`
- [x] README does not claim local pentest
- [x] `local_cli pentest` subcommand removed

### Gate 3 — Tests trustworthy *(needs W4 merged)*

- [x] At least one test fails if `runner.py` pentest handler removed
- [x] No test named `*confirmed*` that only asserts `status=queued`
- [x] SQLi fixture test exists in `worker/tests/`

### Gate 4 — Customer-ready docs/UX *(needs W5 merged)*

- [x] `sentinel doctor` exits non-zero with actionable messages
- [x] Dashboard Team page explains SAST local / pentest cloud split
- [x] Package name consistent (`sentineldev` everywhere or documented alias)

---

## §6 Five workstreams (subagent handoff)

There are **3 architecture paths** in the repo (§2). This plan collapses them into **1 target** using **5 workstreams**. Each workstream is one subagent session.

> **Parallel by default.** See **§6 “Three clocks”** at the top of this doc. **Start all five on day 1.** Gates (§5) = integration checklist, not “wait for W1 before opening W2.”

### File ownership (avoid merge fights)

| Workstream | Branch name | Start | Owns exclusively | Do not touch |
|------------|-------------|-------|------------------|--------------|
| **W1** | `feat/w1-cloud-pentest` | Day 1 | `pentest.py`, `oracle.py`, pentest worker tests, repo migration | `cli/**`, `dashboard/**`, webhook |
| **W2** | `feat/w2-cli-cloud` | Day 1 | `cli/**`, `localEngine.ts`, delete local pentest in `local_engine` / `local_cli` | `pentest.py`, webhook |
| **W3** | `feat/w3-legacy-cleanup` | Day 1 | webhook, dead routes/schemas, `FindingGraph`, `ensure.ts` | local pentest removal (W2), `pentest.py` |
| **W4** | `feat/w4-tests` | Day 1 | new tests, SQLi fixture, conftest scope | production code unless test requires tiny hook |
| **W5** | `feat/w5-ux-docs` | Day 1 | `dashboard/**`, `README.md`, `non-code/` | API schema changes (use §3 D1) |

**Shared files — edit only your slice:**

| File | W1 | W2 | W3 |
|------|----|----|-----|
| `runner.py` | *add* `pentest` handler | — | *remove* `source`/`plan`/`init` handlers |
| `schemas.py` | *add* repo pentest fields | — | *remove* dead request types |

Merge both sides; conflicts here are expected and small.

### Parallel execution diagram

```
  DAY 1 — all agents start
  ────────────────────────
  W1 worker     W2 CLI      W3 legacy     W4 tests     W5 docs
     │             │             │             │            │
     └─────────────┴─────────────┴─────────────┴────────────┘
                              │
                    merge: W1→W4→W2→W3→W5
                              │
                              ▼
                   ③ Integration smoke (Gates 0–4)
```

### W1 — Cloud pentest (make worker execute)

**Gates:** 0  
**Effort:** ~3–5 days  
**Phases:** P0.1–P0.4  

**Goal:** `POST /pentest` → worker claims task → HTTP payloads hit staging URL → oracle updates finding in Postgres.

**In scope (formerly SA-01, 02, 03, 04, 05, 08, 09):**
1. **Repo pentest config** — Alembic migration + model fields: `pentest_mode` (`staging` | `local_worker`), `staging_base_url`, `healthcheck_path`, `boot`, `healthcheck`, `egress_allowlist`. GET/PATCH API with validation per §3 D1.
2. **Runner handler** — `runner.py` handles `kind=pentest`; loads finding + repo config; calls `run_pentest()`.
3. **HTTP dispatch** — `pentest.py` sends payloads to `staging_base_url` via httpx; healthcheck first; trace responses (scrubbed).
4. **Oracle** — Reject agent-only `emit_pentest_result` confirmation; require HTTP response proof or sanitizer output (§1 invariant 5).
5. **Pentest LLM** — `SENTINEL_PENTEST_LLM_API_KEY` on worker (§3 D2); separate from local SAST key.
6. **Confirmation** — Worker writes finding status + `CONFIRMED_EXPLOIT` edge directly; restrict public `POST /findings/{id}/confirm`.
7. **Tests** — `worker/tests/test_runner_pentest.py`, `test_pentest_e2e.py`, `test_oracle.py`; api test enqueue → `process_tasks(1)` → finding updated. Test must **fail** if runner pentest branch removed.

**Key files:** `worker/sentinel_worker/{runner,pentest,oracle,models}.py`, `api/sentinel_api/{main,schemas}.py`, `worker/alembic/`, `api/tests/`, `worker/tests/`

**Acceptance:** All Gate 0 checkboxes in §5.

**Prompt block:**
```text
Workstream W1 from AUDIT.md: Implement cloud pentest end-to-end.

Read §1, §3, §5 Gate 0. Repo pentest config (staging + local_worker modes), runner pentest handler, HTTP payload dispatch, hardened oracle, worker LLM env, worker-internal confirmation, integration tests.

Do NOT edit cli/** (W2) or dashboard/** (W5). Parallel OK with W2/W3/W4/W5 on other paths. Gate 0 must pass on your branch before merge.
```

---

### W2 — CLI → cloud (trigger pentest, kill local pentest)

**Gates:** 1  
**Parallel:** ✅ Start with W1; E2E pentest works after both merge  
**Effort:** ~2–3 days  
**Phases:** P1.1–P1.4, P4.1  

**Goal:** CLI owns SAST only. Pentest = enqueue + poll.

**In scope (formerly SA-06, 07, 12, 16):**
1. **`SentinelApiClient.enqueuePentest()`** — `POST /pentest`; return task/run id.
2. **Rewrite `sentinel pentest`** — enqueue, `runs watch` until terminal, print finding status/evidence. No `runLocalPentest`.
3. **Rewrite `scan --pentest`** — enqueue cloud pentest per ingested finding ID (not local loop).
4. **Remove local pentest** — delete `run_local_pentest`, `local_cli pentest`, `runLocalPentest`, related tests.
5. **Config sync** — `staging_base_url`, `pentest_mode`, boot/healthcheck sync to cloud Repo on `config set` / `init`.
6. **`sentinel doctor`** — git repo, config, cloud health, auth, local engine, LLM key, warn if pentest config missing.

**Key files:** `cli/src/{index,api/client,engine/localEngine,config/sentinel.config}.ts`, `worker/sentinel_worker/{local_engine,local_cli}.py`, `cli/tests/`

**Acceptance:** All Gate 1 checkboxes in §5.

**Prompt block:**
```text
Workstream W2 from AUDIT.md: CLI cloud pentest integration.

Parallel with W1/W3/W4/W5. Add enqueuePentest + poll, rewrite pentest/scan --pentest, remove local pentest code, sync pentest config, implement sentinel doctor. Do NOT edit worker/pentest.py (W1) or webhook (W3). Gate 1 passes after W1 merges.
```

---

### W3 — Legacy cleanup (one architecture in code)

**Gates:** 2  
**Parallel:** ✅ Start day 1; do NOT delete local pentest (W2 owns that)  
**Effort:** ~2 days  
**Phases:** P2.1–P2.4  

**Goal:** Remove the other two architecture paths from product code.

**In scope (formerly SA-10, 11):**
1. **GitHub webhook** — stop storing diff in `tasks.payload`; stop cloud `source` enqueue. Point to `action.yml` for PR SAST + ingest (§3 D5).
2. **Dead API routes** — delete or fix `POST /repos/{id}/plan` (`PlanRequest` NameError); remove unused `InitRequest`/`SourceRequest`.
3. **Dead runner kinds** — remove or hard-fail `source`/`plan`/`init` handlers in `runner.py` (CLI owns SAST).
4. **Dead endpoints** — deprecate/remove `GET /source-files/...` if unused; stop `store_source_snapshot` on paths that shouldn't upload source.
5. **Dead UI/code** — `FindingGraph()` in findings detail page; unused `ensureWorkerContainer` in `ensure.ts` if not needed for `sentinel up`.

**Key files:** `api/sentinel_api/{main,routers/repos,schemas}.py`, `worker/sentinel_worker/{runner,scan,source_store}.py`, `dashboard/`, `cli/src/backend/ensure.ts`, `non-code/shipping.md`

**Acceptance:** All Gate 2 checkboxes in §5.

**Prompt block:**
```text
Workstream W3 from AUDIT.md: Legacy architecture cleanup.

Parallel with all streams. Remove webhook diff scan, dead runner kinds/routes/schemas, narrow source_store. Do NOT remove local pentest (W2) or edit cli/** (W2). Gate 2 after merge.
```

---

### W4 — Tests (trustworthy CI)

**Gates:** 3  
**Parallel:** ✅ Start day 1; pentest E2E may `@pytest.mark.xfail` until W1 merges  
**Effort:** ~1–2 days  
**Phases:** P3.1–P3.4, part of P5.4  

**Goal:** Tests measure real behavior; can't hill-climb on regex mocks.

**In scope (formerly SA-09 partial, 14, 19, 20):**
1. **Fix misleading API tests** — rename `test_pentest_*` that only assert queued; delete firecracker test asserting 200.
2. **Quarantine `_PatternLLM`** — autouse only for webhook smoke tests, not general API tests; document in conftest.
3. **SAST fixture** — restore `worker/tests/fixtures/source/python/sqli.py` + test requiring `read_file` + `emit_finding` (LLM stub at tool boundary, not regex on diff).
4. **Adapter warnings** — surface `adapter.coverage` unmatched files on CLI stderr after scan.

**Key files:** `api/tests/{conftest,test_api}.py`, `worker/tests/`, `cli/src/index.ts`

**Acceptance:** All Gate 3 checkboxes in §5.

**Prompt block:**
```text
Workstream W4 from AUDIT.md: Realign tests.

Parallel with all streams. Fix misleading tests, SQLi fixture, narrow _PatternLLM, adapter warnings on CLI. Pentest E2E xfail OK until W1 lands. Gate 3 after integration merge.
```

---

### W5 — UX + docs (customer-facing truth)

**Gates:** 4  
**Parallel:** ✅ Start day 1; use §3 D1 field names (same as W1), don't add new API fields  
**Effort:** ~2 days  
**Phases:** P4.2–P4.4, P4.3  

**Goal:** Product tells the truth: SAST local, pentest cloud.

**In scope (formerly SA-13, 15):**
1. **Dashboard** — repo pentest config form (staging URL, mode); relabel/remove confusing “Source Retention”; suppression reason prompt (not hardcoded); runs page highlights pentest; copy explaining local SAST / cloud pentest.
2. **README** — architecture diagram matching §1; remove local pentest docs; add doctor, staging URL setup; fix `sentineldev` vs `@sentinel/cli`.
3. **`non-code/README.md` + `stuff.md`** — pentest LLM env var; cloud pentest flow.
4. **Package/version** — align CLI `--version` with package.json.

**Key files:** `dashboard/src/app/{team,findings,runs}/`, `README.md`, `non-code/`

**Acceptance:** All Gate 4 checkboxes in §5.

**Prompt block:**
```text
Workstream W5 from AUDIT.md: Dashboard UX and documentation.

Parallel with all streams. Dashboard pentest config UI + README for §1 architecture. Schema from §3 D1 only. Gate 4 after integration merge.
```

---

## §7 Post-MVP backlog (not a workstream — schedule later)

Do **not** assign these until Gates 0–4 pass. Fold into a future W6 if needed.

| Item | Was | Effort |
|------|-----|--------|
| Node ID composite key migration | SA-17 | 2–3 days |
| GitHub App → CI-only notification | SA-18 | 1–2 days |
| LLM remediation in `pull` | P5.3 | 1–2 days |
| Real graph branch merge | P5.5 | multi-day |

---

## §7b Launch checklist (day 1)

| Agent | Branch | Prompt section |
|-------|--------|----------------|
| A | `feat/w1-cloud-pentest` | W1 prompt block |
| B | `feat/w2-cli-cloud` | W2 prompt block |
| C | `feat/w3-legacy-cleanup` | W3 prompt block |
| D | `feat/w4-tests` | W4 prompt block |
| E | `feat/w5-ux-docs` | W5 prompt block |

**After all PRs merged:** run Gates 0–4 (§5) as one integration smoke session.

One person solo: same five workstreams, but run them **serially** — still use the gates; ignore “day 1 parallel.”

---

## §8 Risk register

| Risk | Mitigation |
|------|------------|
| Hosted worker cannot reach customer localhost | Staging mode only on hosted; document self-hosted for local_worker |
| Pentest without source reads weak payloads | Phase 1 uses vuln_type templates + graph; iterate in P5 |
| Breaking CLI users on local pentest | Release note + major version bump; keep deprecated flag one release if needed |
| Oracle too strict → zero confirmations | Tune HTTP proof thresholds in W1 integration tests |
| Node ID migration breaks prod | Post-MVP backlog (§7); gate on staging DB first |

---

## §9 File reference (quick index)

| Concern | Primary files |
|---------|---------------|
| CLI entry | `cli/src/index.ts`, `cli/src/api/client.ts` |
| Local SAST engine | `worker/sentinel_worker/local_engine.py`, `local_cli.py` |
| Cloud API | `api/sentinel_api/main.py`, `routers/repos.py`, `schemas.py` |
| Worker queue | `worker/sentinel_worker/runner.py`, `worker_main.py`, `task_queue.py` |
| Pentest logic | `worker/sentinel_worker/pentest.py`, `oracle.py`, `vm.py` |
| Graph | `worker/sentinel_worker/graph_query.py`, `scan.py` |
| Models | `worker/sentinel_worker/models.py`, `alembic/versions/` |
| Dashboard | `dashboard/src/app/`, `dashboard/src/lib/api.ts` |
| Tests | `api/tests/`, `worker/tests/`, `cli/tests/` |
| CI scan | `action.yml`, `worker/sentinel_worker/standalone.py` |

---

## §10 Summary

**North star:** CLI runs SAST locally and syncs graph + findings to cloud; cloud worker runs pentest against configured staging URL (or `local_worker` on self-host).

| Clock | Rule |
|-------|------|
| **Start (①)** | All **W1–W5** on day 1, separate branches |
| **Merge (②)** | Each stream when its own tests pass; order `W1→W4→W2→W3→W5` reduces conflicts |
| **Integration (③)** | Gates 0–4 (§5) once combined — product E2E |

**3 architecture paths → 1 target, via 5 parallel workstreams:**

| # | Workstream | One line |
|---|------------|----------|
| W1 | Cloud pentest | Worker executes; HTTP + oracle |
| W2 | CLI → cloud | Enqueue/poll; delete local pentest |
| W3 | Legacy cleanup | Webhook, dead routes, one architecture |
| W4 | Tests | No fake-green pentest/SAST tests |
| W5 | UX + docs | Dashboard + README tell the truth |

Hand off one **W1–W5** prompt block per subagent on day 1. Integration smoke when all are merged.

---

## §11 Resolution (July 8, 2026)

All five workstreams were implemented in parallel and **reconciled into a single tree** (no separate branches; shared-file edits to `runner.py` / `schemas.py` / `main.py` merged in place and verified). One reconciliation commit captures the whole thing.

### Gates — all pass (§5)

| Gate | Owner | Result |
|------|-------|--------|
| 0 — Cloud pentest executes | W1 | ✅ runner handles `kind=pentest`; enqueue→claim→confirm; HTTP dispatch; oracle rejects agent-only proof; regression guard empirically fails if the handler is deleted |
| 1 — CLI integrated | W1+W2 | ✅ no local pentest subprocess; enqueue+poll; `scan --pentest` fans out per finding; repo config readable over the API — **proven live** (below) |
| 2 — Legacy removed | W3 | ✅ webhook stores no diff; `/repos/{id}/plan` gone; `local_cli pentest` gone; README describes cloud pentest only |
| 3 — Tests trustworthy | W4 | ✅ SQLi ground-truth fixture; no fake-green `*confirmed*` tests; handler-removal regression proven |
| 4 — Docs/UX | W5 | ✅ `sentinel doctor` exits non-zero; dashboard explains SAST-local/pentest-cloud; `sentineldev` name + `--version` consistent |

**Combined suites (one tree):** worker 227 passed · api 61 passed (full suite green with `respx` installed) · cli 18 passed · dashboard production build ✓.

### Live E2E smoke (Gate 1, deployed-equivalent)

Because a cloud deploy isn't available here, Gate 1 was proven over **real sockets** instead of a hosted stack (`.context/live_smoke.py`): a real uvicorn API + a real vulnerable staging HTTP server, sharing one DB. Flow, all over HTTP: seed graph+finding → `PATCH`/`GET /repos/{id}/pentest-config` → `POST /pentest` → the **real worker** dispatches real payloads → the target leaks a `psycopg2` SQL error on `' OR '1'='1` → oracle confirms on the **target's own response** → `finding.confirmed=true` + `CONFIRMED_EXPLOIT` edge. Confirmation was asserted to be backed by an actual SQLi request reaching the target (invariant 5), not just a DB flag.

### Environment fix

`api/pyproject.toml` now pins `pythonpath = ["../worker"]` so the API suite always imports the **co-located** `sentinel_worker`, not a stale editable install pointing at another worktree (the Conductor pip-editable caveat). No more hand-set `PYTHONPATH` in local runs or CI.

### Still deferred (not regressions — out of the plan's scope)

- **§7 post-MVP backlog** untouched by design: P5.1 node-ID composite key, P5.2 GitHub-App→CI-only notification, P5.3 LLM remediation in `pull`, P5.5 real 3-way graph merge. (P5.4 adapter warnings *was* pulled in by W4.)
- **LLM-driven pentest payloads** were not exercised live — no pentest LLM is configured in this environment, so the run correctly fell back to **template payloads** (the designed Phase-1 path per §3 D3). A real deploy with `SENTINEL_PENTEST_LLM_API_KEY` set would additionally exercise agent-generated payloads.
