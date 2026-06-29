"""Standalone, one-shot scanner for CI ("scan in place, ship only findings").

This is the engine behind the Sentinel GitHub Action. Unlike the cloud worker
(which pulls jobs from Postgres and is driven by the API), this module runs the
*entire* analysis pipeline locally against an ephemeral SQLite database:

    diff -> tree-sitter graph -> SCA + secret scan + SAST -> findings

The source code never leaves the machine it runs on. Only the resulting finding
metadata is emitted (SARIF / JSON) and, optionally, POSTed to the cloud API via
`--ingest-url`. That is the whole point: a team can wire Sentinel into CI without
uploading their codebase anywhere.

Usage (see `main` / `--help` for the full surface):

    sentinel-scan --repo-name my/repo --base origin/main --head HEAD \
        --provider anthropic --model claude-sonnet-4-6 \
        --sarif sentinel.sarif --fail-on high
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy import select

from .agent import SentinelLLMClient
from .db import create_engine, create_sessionmaker
from .migrations import apply_migrations
from .models import Finding, Node
from .scan import scan_diff

# ── Severity handling ──────────────────────────────────────────────────────
# Ordered least -> most severe so we can compare thresholds numerically.
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITY_ORDER)}

# SARIF only defines: none, note, warning, error.
_SARIF_LEVEL = {
    "info": "note",
    "low": "note",
    "medium": "warning",
    "high": "error",
    "critical": "error",
}


def _severity_rank(severity: str) -> int:
    return SEVERITY_RANK.get((severity or "").lower(), SEVERITY_RANK["medium"])


@dataclass
class ScanFinding:
    vuln_type: str
    severity: str
    title: str
    description: str
    remediation: str
    fingerprint: str
    node_id: str | None = None
    file: str | None = None
    line: int | None = None
    evidence: str | None = None

    def to_dict(self) -> dict:
        return {
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
            "fingerprint": self.fingerprint,
            "node_id": self.node_id,
            "file": self.file,
            "line": self.line,
            "evidence": self.evidence,
        }


@dataclass
class ScanResult:
    repo_name: str
    findings: list[ScanFinding] = field(default_factory=list)
    base_ref: str | None = None
    commit_sha: str | None = None
    run_context: str = "ci"

    @property
    def max_severity_rank(self) -> int:
        return max((_severity_rank(f.severity) for f in self.findings), default=-1)


# ── Git diff computation ───────────────────────────────────────────────────
def _run_git(args: list[str], cwd: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
    )


def compute_git_diff(base: str, head: str, cwd: str) -> str:
    """Return a unified diff of the changes a PR introduces.

    Prefers the merge-base ("three-dot") diff: everything on `head` since it
    diverged from `base`. Falls back to a direct two-dot diff, then to the last
    commit, so the scanner still does something useful on shallow checkouts.
    """
    merge_base = _run_git(["merge-base", base, head], cwd)
    if merge_base.returncode == 0 and merge_base.stdout.strip():
        anchor = merge_base.stdout.strip()
        diff = _run_git(["diff", "--no-color", anchor, head], cwd)
        if diff.returncode == 0:
            return diff.stdout

    # Fallback 1: direct base..head (works when base is reachable but merge-base isn't).
    direct = _run_git(["diff", "--no-color", f"{base}..{head}"], cwd)
    if direct.returncode == 0:
        sys.stderr.write(
            f"sentinel: merge-base unavailable; using direct diff {base}..{head}\n"
        )
        return direct.stdout

    # Fallback 2: last commit only.
    last = _run_git(["diff", "--no-color", "HEAD~1", "HEAD"], cwd)
    if last.returncode == 0:
        sys.stderr.write(
            "sentinel: base ref unavailable; falling back to HEAD~1..HEAD. "
            "For accurate PR scanning, fetch the base branch (fetch-depth: 0).\n"
        )
        return last.stdout

    raise SystemExit(
        f"sentinel: could not compute a diff for base={base!r} head={head!r}. "
        f"git error: {(merge_base.stderr or direct.stderr or last.stderr).strip()}"
    )


def read_diff(args: argparse.Namespace) -> str:
    if args.diff_file:
        if args.diff_file == "-":
            return sys.stdin.read()
        return Path(args.diff_file).read_text()
    return compute_git_diff(args.base, args.head, args.repo_dir)


# ── LLM config resolution ──────────────────────────────────────────────────
_DEFAULT_MODELS = {
    "anthropic": "claude-sonnet-4-6",
    "openai": "gpt-4o",
    "local": "llama3.2",
    "mock": "mock",
}


def resolve_llm(args: argparse.Namespace) -> SentinelLLMClient:
    provider = (args.provider or os.getenv("SENTINEL_PROVIDER") or "mock").lower()
    model = args.model or os.getenv("SENTINEL_MODEL") or _DEFAULT_MODELS.get(provider, "mock")
    endpoint = args.llm_endpoint or os.getenv("SENTINEL_LLM_ENDPOINT")

    api_key = args.api_key or os.getenv("SENTINEL_LLM_API_KEY") or ""
    if not api_key and provider == "anthropic":
        api_key = os.getenv("ANTHROPIC_API_KEY", "")
    if not api_key and provider == "openai":
        api_key = os.getenv("OPENAI_API_KEY", "")

    if provider in ("anthropic", "openai") and not api_key:
        raise SystemExit(
            f"sentinel: provider '{provider}' requires an API key. "
            f"Pass --api-key or set {provider.upper()}_API_KEY / SENTINEL_LLM_API_KEY. "
            f"(Use --provider mock for a secrets+SCA-only scan with no LLM.)"
        )

    return SentinelLLMClient(provider=provider, model=model, api_key=api_key, api_endpoint=endpoint)


# ── Core scan ──────────────────────────────────────────────────────────────
async def _scan(
    *,
    repo_name: str,
    diff: str,
    llm: SentinelLLMClient,
    run_context: str,
    base_ref: str | None,
    commit_sha: str | None,
) -> ScanResult:
    """Run the full pipeline against a throwaway SQLite DB and collect findings."""
    tmpdir = tempfile.mkdtemp(prefix="sentinel-scan-")
    db_path = Path(tmpdir) / "scan.db"
    engine = create_engine(f"sqlite+aiosqlite:///{db_path}")
    result = ScanResult(repo_name=repo_name, base_ref=base_ref, commit_sha=commit_sha, run_context=run_context)
    try:
        await apply_migrations(engine)
        sessionmaker = create_sessionmaker(engine)
        async with sessionmaker() as session:
            async with session.begin():
                run = await scan_diff(
                    session,
                    repo_name,
                    diff,
                    run_context=run_context,
                    base_ref=base_ref,
                    _llm=llm,
                )
                rows = list(await session.scalars(select(Finding).where(Finding.run_id == run.id)))
                for f in rows:
                    file_path: str | None = None
                    line: int | None = None
                    if f.node_id:
                        node = await session.get(Node, f.node_id)
                        if node is not None:
                            file_path = node.file
                            line = node.line_start
                        elif f.node_id.startswith("file:"):
                            file_path = f.node_id.removeprefix("file:")
                    result.findings.append(
                        ScanFinding(
                            vuln_type=f.vuln_type,
                            severity=f.severity,
                            title=f.title,
                            description=f.description,
                            remediation=f.remediation,
                            fingerprint=f.fingerprint,
                            node_id=f.node_id,
                            file=file_path,
                            line=line,
                            evidence=f.evidence,
                        )
                    )
    finally:
        await engine.dispose()
        try:
            db_path.unlink(missing_ok=True)
            Path(tmpdir).rmdir()
        except OSError:
            pass
    result.findings.sort(key=lambda x: (-_severity_rank(x.severity), x.file or "", x.title))
    return result


# ── Output formats ─────────────────────────────────────────────────────────
def to_sarif(result: ScanResult, tool_version: str = "0.0.1") -> dict:
    rules: dict[str, dict] = {}
    sarif_results: list[dict] = []
    for f in result.findings:
        if f.vuln_type not in rules:
            rules[f.vuln_type] = {
                "id": f.vuln_type,
                "name": f.vuln_type.replace("_", " ").title().replace(" ", ""),
                "shortDescription": {"text": f.vuln_type.replace("_", " ")},
            }
        location = {}
        if f.file:
            region: dict = {}
            if f.line and f.line > 0:
                region["startLine"] = f.line
            location = {
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    **({"region": region} if region else {}),
                }
            }
        sarif_results.append(
            {
                "ruleId": f.vuln_type,
                "level": _SARIF_LEVEL.get((f.severity or "").lower(), "warning"),
                "message": {"text": f"{f.title}: {f.description}".strip(": ")},
                "partialFingerprints": {"sentinelFingerprint": f.fingerprint},
                **({"locations": [location]} if location else {}),
                "properties": {
                    "severity": f.severity,
                    "remediation": f.remediation,
                },
            }
        )
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Sentinel",
                        "informationUri": "https://github.com/sentineldev/sentinel",
                        "version": tool_version,
                        "rules": list(rules.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }


def to_findings_json(result: ScanResult) -> dict:
    return {
        "repo_name": result.repo_name,
        "run_context": result.run_context,
        "base_ref": result.base_ref,
        "commit_sha": result.commit_sha,
        "finding_count": len(result.findings),
        "findings": [f.to_dict() for f in result.findings],
    }


# ── Ingest (POST findings to cloud) ────────────────────────────────────────
def post_findings(result: ScanResult, ingest_url: str, token: str | None) -> dict:
    import httpx

    url = ingest_url.rstrip("/") + "/findings/ingest"
    payload = {
        "repo_name": result.repo_name,
        "run_context": result.run_context,
        "commit_sha": result.commit_sha,
        "base_ref": result.base_ref,
        "findings": [
            {
                "vuln_type": f.vuln_type,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "remediation": f.remediation,
                "node_id": f.node_id,
                "file": f.file,
                "line": f.line,
                "evidence": f.evidence,
            }
            for f in result.findings
        ],
    }
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    resp = httpx.post(url, json=payload, headers=headers, timeout=60)
    resp.raise_for_status()
    return resp.json()


# ── Reporting ──────────────────────────────────────────────────────────────
def print_summary(result: ScanResult) -> None:
    out = sys.stderr
    if not result.findings:
        out.write("sentinel: no findings.\n")
        return
    counts: dict[str, int] = {}
    for f in result.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    summary = ", ".join(f"{counts[s]} {s}" for s in reversed(SEVERITY_ORDER) if s in counts)
    out.write(f"sentinel: {len(result.findings)} finding(s) — {summary}\n")
    for f in result.findings:
        loc = f.file or "?"
        if f.line:
            loc += f":{f.line}"
        out.write(f"  [{f.severity.upper():8}] {f.title}  ({f.vuln_type}) {loc}\n")


# ── CLI ────────────────────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sentinel-scan",
        description="Run a Sentinel security scan locally (in CI) and emit findings. "
        "Source code never leaves this machine.",
    )
    p.add_argument("--repo-name", required=True, help="Logical repo name (e.g. owner/repo).")
    p.add_argument("--base", default=os.getenv("SENTINEL_BASE", "origin/main"), help="Base ref for the PR diff.")
    p.add_argument("--head", default=os.getenv("SENTINEL_HEAD", "HEAD"), help="Head ref for the PR diff.")
    p.add_argument("--repo-dir", default=".", help="Path to the git checkout (default: cwd).")
    p.add_argument("--diff-file", help="Read the unified diff from this file ('-' for stdin) instead of git.")

    p.add_argument("--provider", help="LLM provider: anthropic|openai|local|mock (env SENTINEL_PROVIDER; default mock).")
    p.add_argument("--model", help="Model name (env SENTINEL_MODEL).")
    p.add_argument("--api-key", help="LLM API key (env SENTINEL_LLM_API_KEY / ANTHROPIC_API_KEY / OPENAI_API_KEY).")
    p.add_argument("--llm-endpoint", help="Custom LLM endpoint, e.g. Ollama URL (env SENTINEL_LLM_ENDPOINT).")
    p.add_argument(
        "--sast-timeout",
        type=float,
        default=float(os.getenv("SENTINEL_SAST_TIMEOUT_SECONDS", "300")),
        help="Max seconds for the LLM SAST pass (default 300).",
    )

    p.add_argument("--sarif", help="Write SARIF 2.1.0 to this path (for GitHub code scanning).")
    p.add_argument("--json", dest="json_out", help="Write findings JSON to this path.")
    p.add_argument(
        "--fail-on",
        default=os.getenv("SENTINEL_FAIL_ON", "high"),
        choices=[*SEVERITY_ORDER, "none"],
        help="Exit non-zero if any finding is at/above this severity (default high; 'none' never fails).",
    )

    p.add_argument("--ingest-url", help="Cloud API base URL to POST findings to (no source uploaded).")
    p.add_argument("--ingest-token", help="Bearer token for --ingest-url (env SENTINEL_TOKEN).")
    p.add_argument("--run-context", default="ci", help="Run context label stored with findings (default ci).")
    return p


def run(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    # Propagate the SAST timeout into the pipeline (scan.py reads this env).
    os.environ["SENTINEL_SAST_TIMEOUT_SECONDS"] = str(args.sast_timeout)

    diff = read_diff(args)
    if not diff.strip():
        sys.stderr.write("sentinel: empty diff — nothing to scan.\n")
        # Still emit empty reports so downstream steps (SARIF upload) don't fail.
        empty = ScanResult(repo_name=args.repo_name, base_ref=args.base, commit_sha=_resolve_head_sha(args), run_context=args.run_context)
        _write_outputs(args, empty)
        return 0

    llm = resolve_llm(args)
    commit_sha = _resolve_head_sha(args)
    result = asyncio.run(
        _scan(
            repo_name=args.repo_name,
            diff=diff,
            llm=llm,
            run_context=args.run_context,
            base_ref=args.base,
            commit_sha=commit_sha,
        )
    )

    print_summary(result)
    _write_outputs(args, result)

    if args.ingest_url:
        token = args.ingest_token or os.getenv("SENTINEL_TOKEN")
        try:
            resp = post_findings(result, args.ingest_url, token)
            sys.stderr.write(
                f"sentinel: ingested findings -> run {resp.get('run_id')} "
                f"(created={resp.get('created')}, updated={resp.get('updated')})\n"
            )
        except Exception as exc:  # noqa: BLE001 — ingest failure must not crash the scan report
            sys.stderr.write(f"sentinel: WARNING failed to ingest findings: {exc}\n")

    if args.fail_on != "none" and result.max_severity_rank >= _severity_rank(args.fail_on):
        sys.stderr.write(f"sentinel: findings at/above '{args.fail_on}' — failing the check.\n")
        return 1
    return 0


def _resolve_head_sha(args: argparse.Namespace) -> str | None:
    if args.diff_file:
        return None
    proc = _run_git(["rev-parse", args.head], args.repo_dir)
    return proc.stdout.strip() if proc.returncode == 0 else None


def _write_outputs(args: argparse.Namespace, result: ScanResult) -> None:
    if args.sarif:
        Path(args.sarif).write_text(json.dumps(to_sarif(result), indent=2))
        sys.stderr.write(f"sentinel: wrote SARIF -> {args.sarif}\n")
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(to_findings_json(result), indent=2))
        sys.stderr.write(f"sentinel: wrote findings JSON -> {args.json_out}\n")
    if not args.json_out:
        # Default: findings JSON to stdout (machine-readable; summary goes to stderr).
        print(json.dumps(to_findings_json(result), indent=2))


def main() -> None:
    try:
        sys.exit(run())
    except SystemExit:
        raise
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"sentinel: error: {type(exc).__name__}: {exc}\n")
        sys.exit(2)


if __name__ == "__main__":
    main()
