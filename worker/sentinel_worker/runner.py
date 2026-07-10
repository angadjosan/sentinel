from __future__ import annotations

import json
import os

from sqlalchemy.ext.asyncio import AsyncSession

from .models import Account, Finding, Graph, Repo, Run
from .task_queue import ClaimedTask, claim_next_task, complete_task, fail_task


async def run_one_task(db: AsyncSession, *, worker_id: str, account_id: str | None = None, _llm=None) -> str | None:
    claimed = await claim_next_task(db, worker_id=worker_id, account_id=account_id)
    if claimed is None:
        return None
    # Run the task inside a savepoint so that a mid-task DB error (e.g. FK
    # violation from a synthetic node_id) only rolls back the task's writes,
    # leaving the outer transaction valid for fail_task/complete_task.
    try:
        async with db.begin_nested():
            await execute_claimed_task(db, claimed, _llm=_llm)
    except Exception as exc:
        await fail_task(db, task_id=claimed.task.id, error=f"{type(exc).__name__}: {exc}")
        return claimed.task.id
    await complete_task(db, task_id=claimed.task.id)
    return claimed.task.id


async def execute_claimed_task(db: AsyncSession, claimed: ClaimedTask, *, _llm=None) -> None:
    task = claimed.task
    run = await db.get(Run, task.run_id)
    graph = await db.get(Graph, task.graph_id)
    repo = await db.get(Repo, task.repo_id)
    if run is None or graph is None or repo is None:
        raise ValueError("task references missing run, graph, or repo")
    # The cloud worker only runs pentest tasks now. The legacy `source` / `plan`
    # / `init` kinds ran SAST over customer diffs/source on the worker, which the
    # target architecture forbids (§1: SAST is local-only on the CLI machine).
    # Nothing enqueues those kinds anymore; a stale one is a hard error.
    if task.kind == "pentest":
        await execute_pentest_task(db, claimed, repo=repo, graph=graph, _llm=_llm)
        return
    raise ValueError(f"unsupported task kind: {task.kind}")


def _decode_egress_allowlist(raw: str | None) -> list[str]:
    if not raw:
        return []
    try:
        value = json.loads(raw)
    except (ValueError, TypeError):
        return []
    return [str(host) for host in value] if isinstance(value, list) else []


async def _pentest_llm(db: AsyncSession, account: Account | None, _llm):
    """Resolve the pentest-agent LLM (AUDIT.md §3 D2).

    Precedence: an injected test LLM > `SENTINEL_PENTEST_LLM_API_KEY` env on the
    worker > optional `Account.pentest_api_key`. This is separate from the SAST
    key policy — the pentest credential lives on the server side only.
    """
    if _llm is not None:
        return _llm
    from .agent import SentinelLLMClient

    env_key = os.getenv("SENTINEL_PENTEST_LLM_API_KEY")
    provider = os.getenv("SENTINEL_PENTEST_LLM_PROVIDER") or (account.provider if account else None) or "local"
    model = os.getenv("SENTINEL_PENTEST_LLM_MODEL") or (account.model if account else None) or "ollama"
    api_key = env_key or (getattr(account, "pentest_api_key", None) if account else None)
    if provider != "local" and not api_key:
        # No usable credential for a cloud provider — fall back to template payloads.
        return None
    return SentinelLLMClient(provider=provider, model=model, api_key=api_key or "")


async def execute_pentest_task(db: AsyncSession, claimed: ClaimedTask, *, repo: Repo, graph: Graph, _llm=None) -> None:
    """Execute a cloud pentest task (AUDIT.md §6 W1 P0.2–P0.4).

    Loads the finding + repo pentest config, dispatches HTTP payloads to the
    staging URL, and lets the oracle write the finding confirmation directly.
    """
    import hashlib

    from .pentest import PentestRequestContext, run_pentest
    from .pentest_config import resolve_pentest_config
    from .vm import DEFAULT_EGRESS_NETWORK, GvisorSandboxExecutor, apply_egress_rules, egress_rules, ensure_egress_network

    payload = claimed.payload
    finding_id = payload.get("finding_id")
    if not finding_id:
        raise ValueError("pentest task missing finding_id")
    finding = await db.get(Finding, str(finding_id))
    if finding is None:
        raise ValueError("pentest task references missing finding")

    account = await db.get(Account, graph.account_id)

    # Repo config (AUDIT.md §3 D1) is authoritative; task payload may override for
    # ad-hoc runs (e.g. a self-hosted CLI passing boot/healthcheck directly).
    staging_base_url = payload.get("staging_base_url") or repo.staging_base_url
    healthcheck_path = payload.get("healthcheck_path") or repo.healthcheck_path
    egress_allowlist = payload.get("egress_allowlist") or _decode_egress_allowlist(repo.egress_allowlist)
    boot = payload.get("boot") or repo.boot
    healthcheck = payload.get("healthcheck") or repo.healthcheck
    pentest_config_json = payload.get("pentest_config") or getattr(repo, "pentest_config", None)

    # Resolve the full sandbox + egress + secrets + canary + attack-safety config
    # from the structured blob (falls back to safe defaults when absent).
    resolved = resolve_pentest_config(
        pentest_mode=payload.get("pentest_mode") or repo.pentest_mode,
        boot=boot,
        healthcheck=healthcheck,
        egress_allowlist=[str(h) for h in egress_allowlist] if isinstance(egress_allowlist, list) else [],
        pentest_config_json=pentest_config_json,
        seed=f"{repo.id}:{finding_id}",
    )

    # local_worker (self-hosted): boot the target under gVisor on the worker host.
    # staging (hosted default): no on-worker sandbox — HTTP-only probe of staging_base_url.
    executor = None
    proxy_server = None
    sandbox_runtime = "runsc"
    container_name = "sentinel-pentest"
    if resolved.use_local_sandbox:
        from .sandbox_preflight import detect_capabilities

        executor = GvisorSandboxExecutor()
        # Preflight: hard-fail with a clear message if docker is absent; otherwise
        # resolve the runtime (runsc, or runc fallback) and whether we can apply
        # iptables hardening (NET_ADMIN). Degrades gracefully.
        caps = await detect_capabilities(executor)
        sandbox_runtime = caps.runtime
        container_name = f"sentinel-pt-{hashlib.sha256(f'{repo.id}:{finding_id}'.encode()).hexdigest()[:12]}"

        # Ensure the internal egress network exists (target has no direct external
        # route — outbound only via the proxy).
        await ensure_egress_network(executor, DEFAULT_EGRESS_NETWORK)

        # Start the token-scoped egress proxy as the sandbox's only outbound path.
        proxy_server = await _start_egress_proxy(resolved, seed=f"{repo.id}:{finding_id}", healthcheck=healthcheck)

        # Optional hard enforcement: DROP the target's forwarded egress so even a
        # proxy-unaware app can't bypass it. Best-effort; requires NET_ADMIN.
        if caps.hard_egress:
            await apply_egress_rules(executor, egress_rules(resolved.sandbox.vm_ip, []))

    context = PentestRequestContext(
        sanitizer_output=str(payload.get("sanitizer_output", "")),
        behavioral_proof=payload.get("behavioral_proof"),
        proof_detail=str(payload.get("proof_detail", "")),
        sandbox=resolved.sandbox,
        executor=executor,
        staging_base_url=staging_base_url,
        healthcheck_path=healthcheck_path,
        attack_safety=resolved.attack_safety,
        canary_tokens=resolved.canary_tokens,
        broker=resolved.broker,
        sandbox_runtime=sandbox_runtime,
        sandbox_network=DEFAULT_EGRESS_NETWORK,
        container_name=container_name,
    )

    llm = await _pentest_llm(db, account, _llm)
    try:
        # run_pentest creates its own Run, evaluates the oracle, and writes the
        # finding confirmation + CONFIRMED_EXPLOIT edge directly (AUDIT.md §3 D6).
        await run_pentest(db, finding, context, llm=llm)
    finally:
        if proxy_server is not None:
            proxy_server.close()


async def _start_egress_proxy(resolved, *, seed: str, healthcheck: str | None):
    """Build + serve the run's egress proxy and wire the sandbox to route all
    outbound traffic through it (HTTP(S)_PROXY env + a per-run sandbox token)."""
    import hashlib

    from .egress_proxy import build_egress_proxy
    from .vm import DEFAULT_PROXY_HOST_FROM_SANDBOX, _host_from_healthcheck, build_egress_proxy_env

    egress = resolved.sandbox.egress
    allow_hosts = list(egress.allow_hosts) if egress else []
    hc = resolved.sandbox.healthcheck or healthcheck
    hc_host = _host_from_healthcheck(hc) if hc else None
    if hc_host:
        allow_hosts.append(hc_host)

    sandbox_token = hashlib.sha256(f"sandbox-token:{seed}".encode()).hexdigest()[:32]
    proxy = build_egress_proxy(
        allow_hosts=allow_hosts,
        sandbox_token=sandbox_token,
        broker=resolved.broker,
        canary_tokens=resolved.canary_tokens,
        token_scoped=bool(egress.token_scoped) if egress else True,
    )
    # Bind on all interfaces so the sandboxed container can reach the proxy via
    # the docker host gateway (host.docker.internal), not just host-localhost.
    server = await proxy.serve(host="0.0.0.0")
    port = server.sockets[0].getsockname()[1]
    # env is a mutable dict on the frozen config — safe to enrich in place.
    resolved.sandbox.env.update(build_egress_proxy_env(port, host=DEFAULT_PROXY_HOST_FROM_SANDBOX))
    resolved.sandbox.env["SENTINEL_SANDBOX_TOKEN"] = sandbox_token
    return server
