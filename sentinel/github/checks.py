"""Post GitHub Check Run results for PR security reviews."""
import httpx
from sentinel.models import UnifiedReport, CodeSecurityFinding, DepFinding

GITHUB_API = "https://api.github.com"

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_ANNOTATION_LEVEL = {"critical": "failure", "high": "failure", "medium": "warning", "low": "notice", "info": "notice"}


async def post_check_run(
    repo: str,          # "owner/repo"
    head_sha: str,
    report: UnifiedReport,
    installation_token: str,  # GitHub App installation access token
) -> str:
    """
    Create a GitHub Check Run with findings as annotations.

    1. POST /repos/{owner}/{repo}/check-runs with:
       - name: "Sentinel Security Review"
       - head_sha: head_sha
       - status: "completed"
       - conclusion: "action_required" if any high/critical findings, else "success"
       - output: { title, summary, text, annotations }

    2. Annotations come from code_security_findings:
       { path, start_line, end_line, annotation_level, message, title }
       annotation_level: "failure" for critical/high, "warning" for medium, "notice" for low

    3. Max 50 annotations per Check Run (GitHub limit) — take top 50 by severity.

    4. Return the check run URL from the response.

    Use httpx.AsyncClient with Authorization: Bearer {token} and
    Accept: application/vnd.github+json headers.
    """
    annotations = _build_annotations(report.code_security_findings)

    total = report.total_findings
    dep_count = len(report.dep_findings)
    code_count = len(report.code_security_findings)

    title = f"Sentinel Security Review — {total} finding(s)"
    summary = _build_summary(report)
    text = (
        f"**Dependency findings:** {dep_count}\n"
        f"**Code security findings:** {code_count}\n"
        f"**Risk score:** {report.risk_score}/100"
    )

    payload = {
        "name": "Sentinel Security Review",
        "head_sha": head_sha,
        "status": "completed",
        "conclusion": _conclusion(report),
        "output": {
            "title": title,
            "summary": summary,
            "text": text,
            "annotations": annotations,
        },
    }

    headers = {
        "Authorization": f"Bearer {installation_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{GITHUB_API}/repos/{repo}/check-runs",
            json=payload,
            headers=headers,
            timeout=30.0,
        )
        response.raise_for_status()
        data = response.json()
        return data["html_url"]


async def post_pr_comment(
    repo: str,
    pr_number: int,
    report: UnifiedReport,
    installation_token: str,
) -> None:
    """
    Post a summary comment on the PR.

    Format:
    ## Sentinel Security Review

    **Risk Score: {score}/100**

    ### Dependency Findings ({n})
    | Package | CVE | Severity | Fix |
    |---------|-----|----------|-----|
    | ... top 5 ... |

    ### Code Security Findings ({n})
    | File | Category | Severity | Issue |

    If no findings: "✅ No security issues found."

    POST to /repos/{owner}/{repo}/issues/{pr_number}/comments
    """
    body = _build_pr_comment(report)

    headers = {
        "Authorization": f"Bearer {installation_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{GITHUB_API}/repos/{repo}/issues/{pr_number}/comments",
            json={"body": body},
            headers=headers,
            timeout=30.0,
        )
        response.raise_for_status()


def _conclusion(report: UnifiedReport) -> str:
    """Return 'action_required' if critical/high findings, else 'success'."""
    for f in report.dep_findings + report.code_security_findings:  # type: ignore[operator]
        if hasattr(f, 'severity') and f.severity in ("critical", "high"):
            return "action_required"
    return "success"


def _build_summary(report: UnifiedReport) -> str:
    """Build the Check Run output.summary field."""
    total = report.total_findings
    if total == 0:
        return "No security issues found."

    parts: list[str] = [f"Found **{total}** security finding(s) with a risk score of **{report.risk_score}/100**."]

    # Tally by severity across dep + code findings
    severity_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in report.dep_findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
    for f in report.code_security_findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    summary_parts = []
    for sev in ("critical", "high", "medium", "low", "info"):
        count = severity_counts.get(sev, 0)
        if count:
            summary_parts.append(f"{count} {sev}")

    if summary_parts:
        parts.append("Severity breakdown: " + ", ".join(summary_parts) + ".")

    return " ".join(parts)


def _build_annotations(findings: list[CodeSecurityFinding]) -> list[dict]:
    """Convert CodeSecurityFinding list to GitHub annotation dicts (max 50, top by severity)."""
    # Sort by severity order (critical first)
    sorted_findings = sorted(
        findings,
        key=lambda f: _SEVERITY_ORDER.get(f.severity, 99),
    )
    top = sorted_findings[:50]

    annotations = []
    for f in top:
        line = f.line if f.line is not None else 1
        annotation: dict = {
            "path": f.file,
            "start_line": line,
            "end_line": line,
            "annotation_level": _ANNOTATION_LEVEL.get(f.severity, "notice"),
            "message": f.explanation,
            "title": f"{f.category.replace('_', ' ').title()} ({f.severity.upper()})",
        }
        if f.cwe_id:
            annotation["title"] += f" [{f.cwe_id}]"
        annotations.append(annotation)

    return annotations


def _build_pr_comment(report: UnifiedReport) -> str:
    """Build the full PR comment body."""
    lines: list[str] = ["## Sentinel Security Review", ""]
    lines.append(f"**Risk Score: {report.risk_score}/100**")
    lines.append("")

    if report.total_findings == 0:
        lines.append("✅ No security issues found.")
        return "\n".join(lines)

    # Dependency findings table (top 5)
    dep_count = len(report.dep_findings)
    lines.append(f"### Dependency Findings ({dep_count})")
    if dep_count == 0:
        lines.append("_None_")
    else:
        lines.append("| Package | CVE | Severity | Fix |")
        lines.append("|---------|-----|----------|-----|")
        sorted_deps = sorted(
            report.dep_findings,
            key=lambda f: _SEVERITY_ORDER.get(f.severity, 99),
        )
        for dep in sorted_deps[:5]:
            fix = dep.fix_version or "No fix available"
            lines.append(f"| `{dep.package}@{dep.version}` | {dep.cve_id} | {dep.severity} | {fix} |")
        if dep_count > 5:
            lines.append(f"_…and {dep_count - 5} more. See full report._")
    lines.append("")

    # Code security findings table (top 5)
    code_count = len(report.code_security_findings)
    lines.append(f"### Code Security Findings ({code_count})")
    if code_count == 0:
        lines.append("_None_")
    else:
        lines.append("| File | Category | Severity | Issue |")
        lines.append("|------|----------|----------|-------|")
        sorted_code = sorted(
            report.code_security_findings,
            key=lambda f: _SEVERITY_ORDER.get(f.severity, 99),
        )
        for cf in sorted_code[:5]:
            loc = f"{cf.file}:{cf.line}" if cf.line else cf.file
            category = cf.category.replace("_", " ").title()
            explanation = cf.explanation[:80] + "…" if len(cf.explanation) > 80 else cf.explanation
            lines.append(f"| `{loc}` | {category} | {cf.severity} | {explanation} |")
        if code_count > 5:
            lines.append(f"_…and {code_count - 5} more. See full report._")

    return "\n".join(lines)
