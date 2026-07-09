"""Console-script entry point the Node CLI shells out to for local execution.

`sentinel-local source` / `sentinel-local plan` run the full analysis pipeline
on this machine — diff computed locally, LLM called locally with a locally
configured API key, source read from the local working tree — and print a
single JSON result line to stdout for the Node CLI to parse. Everything else
(progress, per-finding summary) goes to stderr so stdout stays machine-only.

Reuses standalone.py's diff computation and LLM-provider resolution rather
than duplicating them; the difference from `standalone.py` is that this entry
point optionally syncs with the Sentinel cloud (pulling graph context, pushing
back the graph delta + findings) instead of running fully ephemeral.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from .local_engine import (
    GraphDelta,
    push_results_to_cloud,
    run_local_init,
    run_local_plan_review,
    run_local_source_scan,
)
from .standalone import SEVERITY_ORDER, ScanResult, _resolve_head_sha, _severity_rank, read_diff, resolve_llm


def _add_common_llm_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--provider", help="LLM provider: anthropic|openai|local|mock (env SENTINEL_PROVIDER).")
    p.add_argument("--model", help="Model name (env SENTINEL_MODEL).")
    p.add_argument("--api-key", help="LLM API key (env SENTINEL_LLM_API_KEY / ANTHROPIC_API_KEY / OPENAI_API_KEY).")
    p.add_argument("--llm-endpoint", help="Custom LLM endpoint, e.g. an Ollama URL (env SENTINEL_LLM_ENDPOINT).")


def _add_common_cloud_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--api-url", help="Sentinel cloud API base URL. Omit to run fully offline — no graph sync.")
    p.add_argument("--api-token", help="Bearer token for --api-url.")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sentinel-local",
        description="Run a Sentinel scan or plan review locally. Source code and diffs never leave this machine.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="Build the full graph locally from every tracked file and push it.")
    init.add_argument("--repo-name", required=True)
    init.add_argument("--repo-dir", default=".")
    _add_common_llm_args(init)
    _add_common_cloud_args(init)

    source = sub.add_parser("source", help="Scan the current git diff locally.")
    source.add_argument("--repo-name", required=True)
    source.add_argument("--repo-dir", default=".")
    source.add_argument("--base", default="HEAD")
    source.add_argument("--head", default="HEAD")
    source.add_argument("--diff-file", help="Read the unified diff from this file ('-' for stdin) instead of git.")
    source.add_argument("--run-context", default="local")
    source.add_argument(
        "--fail-on",
        default="info",
        choices=[*SEVERITY_ORDER, "none"],
        help="Exit 1 if any finding is at/above this severity (default info — i.e. any finding).",
    )
    _add_common_llm_args(source)
    _add_common_cloud_args(source)

    plan = sub.add_parser("plan", help="Review a plan/design doc locally.")
    plan.add_argument("--repo-name", required=True)
    plan.add_argument("--repo-dir", default=".")
    plan.add_argument("--content-file", help="Read plan content from this file ('-' for stdin).")
    plan.add_argument("--with-retry", action="store_true")
    _add_common_llm_args(plan)
    _add_common_cloud_args(plan)

    # NOTE: the `pentest` subcommand was removed (AUDIT.md §3 D4). Pentest is no
    # longer run on this machine — `sentinel pentest` in the Node CLI enqueues a
    # cloud pentest (POST /pentest) and the cloud worker executes it.

    return p


def _read_content(path: str | None) -> str:
    if path is None or path == "-":
        return sys.stdin.read()
    return Path(path).read_text()


def _push_or_warn(**kwargs) -> dict:
    """Push results, degrading gracefully on failure.

    A scan that ran successfully locally must still report its real findings
    even if the cloud is unreachable or briefly out of sync (network blip,
    rolling deploy, etc.) — the local result is valid on its own. Mirrors the
    existing `standalone.py` --ingest-url failure handling.
    """
    try:
        return push_results_to_cloud(**kwargs)
    except Exception as exc:  # noqa: BLE001 — a push failure must not discard local results
        sys.stderr.write(f"sentinel: WARNING failed to push results to the cloud: {exc}\n")
        return {"error": str(exc)}


def run(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    llm = resolve_llm(args)

    if args.command == "init":
        delta, local_run_id, local_trace_path = asyncio.run(
            run_local_init(repo_name=args.repo_name, repo_dir=args.repo_dir, llm=llm)
        )
        push_response: dict = {}
        if args.api_url:
            push_response = _push_or_warn(
                api_url=args.api_url,
                token=args.api_token,
                repo_name=args.repo_name,
                run_context="init",
                commit_sha=None,
                base_ref=None,
                scan=ScanResult(repo_name=args.repo_name),
                delta=delta,
            )
        sys.stderr.write(f"sentinel: graph built — {len(delta.nodes)} nodes, {len(delta.edges)} edges.\n")
        sys.stderr.write(f"sentinel: full trace saved locally -> {local_trace_path}\n")
        print(
            json.dumps(
                {
                    "nodes": len(delta.nodes),
                    "edges": len(delta.edges),
                    "local_run_id": local_run_id,
                    "local_trace_path": local_trace_path,
                    "push": push_response,
                }
            )
        )
        return 0

    if args.command == "source":
        diff = read_diff(args)
        if not diff.strip():
            print(json.dumps({"findings": [], "finding_count": 0, "graph_nodes_pushed": 0, "graph_edges_pushed": 0, "push": {}}))
            return 0
        commit_sha = _resolve_head_sha(args)
        result = asyncio.run(
            run_local_source_scan(
                repo_name=args.repo_name,
                repo_dir=args.repo_dir,
                diff=diff,
                llm=llm,
                run_context=args.run_context,
                base_ref=args.base,
                commit_sha=commit_sha,
                api_url=args.api_url,
                api_token=args.api_token,
            )
        )
        push_response: dict = {}
        if args.api_url:
            push_response = _push_or_warn(
                api_url=args.api_url,
                token=args.api_token,
                repo_name=args.repo_name,
                run_context=args.run_context,
                commit_sha=commit_sha,
                base_ref=args.base,
                scan=result.scan,
                delta=result.delta,
            )
        for f in result.scan.findings:
            loc = f.file or "?"
            if f.line:
                loc += f":{f.line}"
            sys.stderr.write(f"  [{f.severity.upper():8}] {f.title}  ({f.vuln_type}) {loc}\n")
        sys.stderr.write(f"sentinel: full trace saved locally -> {result.local_trace_path}\n")
        print(
            json.dumps(
                {
                    "findings": [f.to_dict() for f in result.scan.findings],
                    "finding_count": len(result.scan.findings),
                    "graph_nodes_pushed": len(result.delta.nodes),
                    "graph_edges_pushed": len(result.delta.edges),
                    # AUDIT.md §6 W4 P5.4: files no framework adapter matched.
                    "adapter_unmatched_files": result.adapter_unmatched_files,
                    "local_run_id": result.local_run_id,
                    "local_trace_path": result.local_trace_path,
                    "push": push_response,
                }
            )
        )
        if args.fail_on != "none" and result.scan.max_severity_rank >= _severity_rank(args.fail_on):
            return 1
        return 0

    if args.command == "plan":
        content = _read_content(args.content_file)
        scan, local_run_id, local_trace_path = asyncio.run(
            run_local_plan_review(
                repo_name=args.repo_name,
                repo_dir=args.repo_dir,
                content=content,
                llm=llm,
                with_retry=args.with_retry,
            )
        )
        push_response = {}
        if args.api_url:
            push_response = _push_or_warn(
                api_url=args.api_url,
                token=args.api_token,
                repo_name=args.repo_name,
                run_context="plan",
                commit_sha=None,
                base_ref=None,
                scan=scan,
                delta=GraphDelta(),
            )
        for f in scan.findings:
            sys.stderr.write(f"  [{f.severity.upper():8}] {f.title}  ({f.vuln_type})\n")
        sys.stderr.write(f"sentinel: full trace saved locally -> {local_trace_path}\n")
        print(
            json.dumps(
                {
                    "findings": [f.to_dict() for f in scan.findings],
                    "finding_count": len(scan.findings),
                    "local_run_id": local_run_id,
                    "local_trace_path": local_trace_path,
                    "push": push_response,
                }
            )
        )
        return 1 if scan.findings else 0

    return 2


def main() -> None:
    try:
        sys.exit(run())
    except SystemExit:
        raise
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"sentinel-local: error: {type(exc).__name__}: {exc}\n")
        sys.exit(2)


if __name__ == "__main__":
    main()
