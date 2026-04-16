"""
Passive attack surface enumeration for a GitHub repository.

Stages:
1. Domain extraction — find domains referenced in the repo
2. DNS resolution — confirm which subdomains are live
3. TLS inspection — check cert validity, expiry, mismatch
4. Dangling CNAME detection — identify records pointing to unclaimed services
"""
from __future__ import annotations

import asyncio
import logging
import re
import socket
import ssl
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx
import dns.resolver
import dns.exception

from sentinel.models import AttackSurfaceFinding, Severity

logger = logging.getLogger(__name__)

# ── 1. Domain/subdomain extraction ──────────────────────────────────────────

DOMAIN_REGEX = re.compile(
    r'https?://([a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})(?:[/\s"\']|$)'
)
ENV_DOMAIN_REGEX = re.compile(
    r'(?:BASE_URL|API_URL|DOMAIN|HOST|FRONTEND_URL|BACKEND_URL)\s*[=:]\s*["\']?https?://([a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})'
)

# Domains to always skip — noisy / well-known / not customer-owned
_SKIP_DOMAINS = {
    "localhost",
    "example.com",
    "github.com",
    "githubusercontent.com",
    "npmjs.com",
    "pypi.org",
    "python.org",
    "nodejs.org",
    "googleapis.com",
    "gstatic.com",
    "cloudflare.com",
    "fastly.net",
    "unpkg.com",
    "jsdelivr.net",
    "cdnjs.cloudflare.com",
    "shields.io",
    "badge.fury.io",
    "travis-ci.org",
    "travis-ci.com",
    "circleci.com",
    "codecov.io",
    "readthedocs.io",
    "readthedocs.org",
    "docs.rs",
    "crates.io",
    "rubygems.org",
    "packagist.org",
}

_SKIP_DOMAIN_PATTERNS = re.compile(
    r'(^|\.)('
    r'amazonaws\.com|'
    r'cloudfront\.net|'
    r'127\.0\.0\.1|'
    r'0\.0\.0\.0|'
    r'schema\.org|'
    r'w3\.org|'
    r'mozilla\.org|'
    r'ietf\.org'
    r')$'
)

_SOURCE_EXTENSIONS = {
    ".yml", ".yaml", ".env", ".json", ".toml",
    ".py", ".js", ".ts", ".jsx", ".tsx", ".md",
    ".txt", ".ini", ".cfg", ".conf", ".sh",
}

_SKIP_DIRS = {"node_modules", ".git", "dist", "build", "__pycache__", ".venv", "venv"}


def _is_skippable_domain(domain: str) -> bool:
    """Return True if this domain should be excluded from scanning."""
    domain_lower = domain.lower()
    if domain_lower in _SKIP_DOMAINS:
        return True
    if _SKIP_DOMAIN_PATTERNS.search(domain_lower):
        return True
    # Skip raw IPs
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain_lower):
        return True
    return False


def _extract_root_domain(fqdn: str) -> str:
    """
    Return the registrable root domain from an FQDN.
    Simple heuristic: last two labels (or three for known multi-part TLDs).
    """
    parts = fqdn.rstrip(".").lower().split(".")
    if len(parts) <= 2:
        return fqdn.lower()
    # Handle common multi-part TLDs: co.uk, com.au, etc.
    known_second_level = {"co", "com", "net", "org", "gov", "edu", "ac"}
    if len(parts) >= 3 and parts[-2] in known_second_level and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def extract_domains_from_repo(repo_path: str) -> set[str]:
    """
    Walk repo for domains referenced in source files.
    Look in: *.yml, *.yaml, *.env*, *.json, *.toml, *.py, *.js, *.ts, *.md
    Skip: node_modules, .git, dist, build, __pycache__
    Extract domains via DOMAIN_REGEX and ENV_DOMAIN_REGEX.
    Return deduplicated set of root domains (e.g. "example.com" not "api.example.com").
    Skip localhost, 127.0.0.1, example.com, github.com, amazonaws.com patterns.
    """
    root: Path = Path(repo_path)
    found_roots: set[str] = set()

    def _should_skip_dir(d: Path) -> bool:
        return d.name in _SKIP_DIRS

    def _should_scan_file(f: Path) -> bool:
        # Accept files whose suffix matches, or files that start with ".env"
        name = f.name.lower()
        if name.startswith(".env"):
            return True
        return f.suffix.lower() in _SOURCE_EXTENSIONS

    for path in root.rglob("*"):
        # Skip hidden/ignored directories
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if not path.is_file():
            continue
        if not _should_scan_file(path):
            continue

        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        candidates: set[str] = set()
        for m in DOMAIN_REGEX.finditer(text):
            candidates.add(m.group(1).lower())
        for m in ENV_DOMAIN_REGEX.finditer(text):
            candidates.add(m.group(1).lower())

        for domain in candidates:
            if _is_skippable_domain(domain):
                continue
            root_domain = _extract_root_domain(domain)
            if not _is_skippable_domain(root_domain):
                found_roots.add(root_domain)

    logger.debug("extract_domains_from_repo found %d root domains", len(found_roots))
    return found_roots


def extract_subdomains(root_domains: set[str], repo_path: str) -> set[str]:
    """
    Extract all subdomains from the repo that belong to root_domains.
    Also include www.<domain> for each root domain.
    Return set of FQDNs.
    """
    root = Path(repo_path)
    fqdns: set[str] = set()

    # Always include www. for each root domain
    for rd in root_domains:
        fqdns.add(rd)
        fqdns.add(f"www.{rd}")

    if not root_domains:
        return fqdns

    # Build a pattern to match any subdomain of known root domains
    escaped = [re.escape(rd) for rd in root_domains]
    subdomain_pattern = re.compile(
        r'(?:^|["\'\s(])([a-zA-Z0-9][a-zA-Z0-9\-\.]*\.(?:' +
        "|".join(escaped) +
        r'))(?:["\'\s)/]|$)',
        re.IGNORECASE,
    )

    for path in root.rglob("*"):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if not path.is_file():
            continue
        name = path.name.lower()
        if not (name.startswith(".env") or path.suffix.lower() in _SOURCE_EXTENSIONS):
            continue

        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        for m in subdomain_pattern.finditer(text):
            candidate = m.group(1).lower().strip(".")
            if not _is_skippable_domain(candidate):
                fqdns.add(candidate)

    logger.debug("extract_subdomains found %d FQDNs total", len(fqdns))
    return fqdns


# ── 2. DNS resolution ────────────────────────────────────────────────────────

async def resolve_subdomain(fqdn: str) -> dict:
    """
    Try A, CNAME resolution for fqdn.
    Return: {"fqdn": str, "live": bool, "cname": Optional[str], "ips": list[str], "error": Optional[str]}
    Uses dns.resolver.Resolver(). Catches NXDOMAIN, NoAnswer, Timeout.
    """
    result: dict = {
        "fqdn": fqdn,
        "live": False,
        "cname": None,
        "ips": [],
        "error": None,
    }

    loop = asyncio.get_event_loop()

    def _resolve_sync() -> dict:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10

        # Try CNAME first
        cname_target: Optional[str] = None
        try:
            cname_answers = resolver.resolve(fqdn, "CNAME")
            for rdata in cname_answers:
                cname_target = str(rdata.target).rstrip(".")
                break
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.exception.Timeout, dns.resolver.NoNameservers):
            pass
        except Exception:
            pass

        # Try A record
        ips: list[str] = []
        try:
            a_answers = resolver.resolve(fqdn, "A")
            for rdata in a_answers:
                ips.append(str(rdata))
        except dns.resolver.NXDOMAIN:
            result["error"] = "NXDOMAIN"
            return result
        except dns.resolver.NoAnswer:
            # Might still be live via CNAME with no direct A record
            pass
        except dns.exception.Timeout:
            result["error"] = "DNS timeout"
            return result
        except dns.resolver.NoNameservers:
            result["error"] = "No nameservers"
            return result
        except Exception as exc:
            result["error"] = str(exc)
            return result

        live = bool(ips or cname_target)
        return {
            "fqdn": fqdn,
            "live": live,
            "cname": cname_target,
            "ips": ips,
            "error": None,
        }

    try:
        resolved = await loop.run_in_executor(None, _resolve_sync)
        return resolved
    except Exception as exc:
        result["error"] = str(exc)
        return result


# ── 3. TLS inspection ────────────────────────────────────────────────────────

def check_tls(fqdn: str, port: int = 443, timeout: float = 5.0) -> dict:
    """
    Connect to fqdn:443 and inspect TLS cert.
    Return: {
        "valid": bool,
        "expired": bool,
        "days_until_expiry": Optional[int],
        "cn": Optional[str],
        "san": list[str],
        "mismatch": bool,  # fqdn not in CN or SAN
        "error": Optional[str]
    }
    """
    result: dict = {
        "valid": False,
        "expired": False,
        "days_until_expiry": None,
        "cn": None,
        "san": [],
        "mismatch": False,
        "error": None,
    }

    try:
        context = ssl.create_default_context()
        with socket.create_connection((fqdn, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=fqdn) as ssock:
                cert = ssock.getpeercert()

        # Extract CN
        subject = dict(x[0] for x in cert.get("subject", []))
        cn = subject.get("commonName")
        result["cn"] = cn

        # Extract SANs
        san_list: list[str] = []
        for san_type, san_value in cert.get("subjectAltName", []):
            if san_type == "DNS":
                san_list.append(san_value.lower())
        result["san"] = san_list

        # Expiry
        not_after_str = cert.get("notAfter", "")
        if not_after_str:
            # Format: "Apr 15 12:00:00 2026 GMT"
            not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
            not_after = not_after.replace(tzinfo=timezone.utc)
            now = datetime.now(tz=timezone.utc)
            days_left = (not_after - now).days
            result["days_until_expiry"] = days_left
            result["expired"] = days_left < 0

        # Hostname mismatch check
        fqdn_lower = fqdn.lower()
        in_cn = cn and _cert_name_matches(fqdn_lower, cn.lower())
        in_san = any(_cert_name_matches(fqdn_lower, s) for s in san_list)
        result["mismatch"] = not (in_cn or in_san)
        result["valid"] = not result["expired"] and not result["mismatch"]

    except ssl.SSLCertVerificationError as exc:
        result["error"] = f"SSL verification error: {exc}"
        result["valid"] = False
    except ssl.SSLError as exc:
        result["error"] = f"SSL error: {exc}"
        result["valid"] = False
    except socket.timeout:
        result["error"] = "Connection timed out"
    except ConnectionRefusedError:
        result["error"] = "Connection refused"
    except OSError as exc:
        result["error"] = str(exc)
    except Exception as exc:
        result["error"] = str(exc)

    return result


def _cert_name_matches(hostname: str, cert_name: str) -> bool:
    """Check if a hostname matches a cert CN or SAN entry (supports wildcards)."""
    if cert_name.startswith("*."):
        # Wildcard: *.example.com matches foo.example.com but not foo.bar.example.com
        suffix = cert_name[2:]  # "example.com"
        if hostname == suffix:
            return False
        if hostname.endswith("." + suffix):
            # Make sure only one label is wildcarded
            prefix = hostname[: -(len(suffix) + 1)]
            return "." not in prefix
        return False
    return hostname == cert_name


# ── 4. Dangling CNAME detection ──────────────────────────────────────────────

DANGLING_PATTERNS = [
    # (regex_pattern, service_name)
    (re.compile(r"\.s3[.-].*\.amazonaws\.com$", re.I), "AWS S3"),
    (re.compile(r"\.s3\.amazonaws\.com$", re.I), "AWS S3"),
    (re.compile(r"^s3\.amazonaws\.com$", re.I), "AWS S3"),
    (re.compile(r"\.herokuapp\.com$", re.I), "Heroku"),
    (re.compile(r"\.github\.io$", re.I), "GitHub Pages"),
    (re.compile(r"\.netlify\.app$", re.I), "Netlify"),
    (re.compile(r"\.vercel\.app$", re.I), "Vercel"),
    (re.compile(r"\.azurewebsites\.net$", re.I), "Azure"),
    (re.compile(r"\.trafficmanager\.net$", re.I), "Azure Traffic Manager"),
    (re.compile(r"\.cloudapp\.azure\.com$", re.I), "Azure Cloud"),
    (re.compile(r"\.zendesk\.com$", re.I), "Zendesk"),
    (re.compile(r"\.helpscoutdocs\.com$", re.I), "HelpScout"),
    (re.compile(r"\.ghost\.io$", re.I), "Ghost"),
    (re.compile(r"\.surge\.sh$", re.I), "Surge"),
    (re.compile(r"\.webflow\.io$", re.I), "Webflow"),
    (re.compile(r"\.fastly\.net$", re.I), "Fastly"),
    (re.compile(r"\.pantheonsite\.io$", re.I), "Pantheon"),
]


def _check_s3_bucket(bucket_name: str) -> bool:
    """
    Return True if the S3 bucket appears unclaimed (returns 404/NoSuchBucket).
    Uses httpx synchronously; treats errors as "not confirmed dangling".
    """
    try:
        url = f"https://{bucket_name}.s3.amazonaws.com/"
        with httpx.Client(timeout=5.0, follow_redirects=False) as client:
            resp = client.get(url)
        # NoSuchBucket returns 404 with XML body mentioning NoSuchBucket
        if resp.status_code == 404 and b"NoSuchBucket" in resp.content:
            return True
        # AccessDenied means bucket exists but is private — not dangling
        return False
    except Exception:
        return False


def is_dangling_cname(cname: str) -> tuple[bool, str]:
    """
    Check if a CNAME target looks like an unclaimed cloud service.
    Returns (is_dangling: bool, service_name: str).
    For S3: verify the bucket 404s with NoSuchBucket.
    For others: pattern match heuristic (v1).
    """
    cname_lower = cname.lower().rstrip(".")

    for pattern, service_name in DANGLING_PATTERNS:
        if pattern.search(cname_lower):
            # Extra verification for S3
            if service_name == "AWS S3":
                # Extract bucket name from subdomain portion
                # e.g. "mybucket.s3.amazonaws.com" -> bucket = "mybucket"
                bucket_match = re.match(r'^([a-z0-9][a-z0-9\-\.]+)\.s3', cname_lower)
                if bucket_match:
                    bucket_name = bucket_match.group(1)
                    if _check_s3_bucket(bucket_name):
                        return True, service_name
                    # If check failed (access denied / error), not confirmed dangling
                    return False, ""
                # Pattern matched but couldn't extract bucket — flag anyway
                return True, service_name

            # For other services, pattern match is sufficient for v1
            return True, service_name

    return False, ""


# ── 5. Main scanner ──────────────────────────────────────────────────────────

async def run_surface_scan(
    repo_path: str,
    extra_domains: list[str] | None = None,
) -> list[AttackSurfaceFinding]:
    """
    Full attack surface scan:
    1. Extract domains + subdomains from repo
    2. Add extra_domains if provided
    3. DNS resolve all candidates concurrently (asyncio.gather, semaphore=20)
    4. For live subdomains: check TLS, check dangling CNAME
    5. Convert findings to AttackSurfaceFinding list

    Finding types:
    - subdomain/live: info-level inventory entry for live subdomains
    - tls/expired: high severity if cert expired
    - tls/expiring_soon: medium if < 30 days to expiry
    - tls/mismatch: high if hostname mismatch
    - dns/dangling: critical if CNAME points to unclaimed service
    """
    findings: list[AttackSurfaceFinding] = []
    semaphore = asyncio.Semaphore(20)

    # ── Stage 1: static domain extraction ────────────────────────────────────
    logger.info("Stage 1: extracting domains from %s", repo_path)
    root_domains = extract_domains_from_repo(repo_path)

    if extra_domains:
        for d in extra_domains:
            d = d.lower().strip()
            root_domains.add(_extract_root_domain(d))

    if not root_domains:
        logger.info("No domains found in repo — skipping surface scan")
        return findings

    candidates = extract_subdomains(root_domains, repo_path)

    # Also add any extra_domains FQDNs directly
    if extra_domains:
        for d in extra_domains:
            candidates.add(d.lower().strip())

    logger.info(
        "Stage 2: DNS-resolving %d candidate FQDNs (root domains: %s)",
        len(candidates),
        ", ".join(sorted(root_domains)[:10]),
    )

    # ── Stage 2: concurrent DNS resolution ───────────────────────────────────
    async def _resolve_with_sem(fqdn: str) -> dict:
        async with semaphore:
            return await resolve_subdomain(fqdn)

    dns_results = await asyncio.gather(
        *[_resolve_with_sem(fqdn) for fqdn in candidates],
        return_exceptions=False,
    )

    live_results = [r for r in dns_results if r.get("live")]
    logger.info("%d / %d FQDNs are live", len(live_results), len(candidates))

    # ── Stage 3 & 4: TLS + dangling CNAME (run in thread pool) ──────────────
    loop = asyncio.get_event_loop()

    async def _tls_and_dangling(dns_result: dict) -> list[AttackSurfaceFinding]:
        fqdn: str = dns_result["fqdn"]
        cname: Optional[str] = dns_result.get("cname")
        ips: list[str] = dns_result.get("ips", [])
        local_findings: list[AttackSurfaceFinding] = []

        # Inventory entry — always emit for live hosts
        local_findings.append(
            AttackSurfaceFinding(
                asset=fqdn,
                asset_type="subdomain",
                issue="Live subdomain discovered",
                severity="info",
                details={
                    "ips": ips,
                    "cname": cname,
                },
            )
        )

        # ── Dangling CNAME check ─────────────────────────────────────────────
        if cname:
            async with semaphore:
                dangling, service = await loop.run_in_executor(
                    None, is_dangling_cname, cname
                )
            if dangling:
                local_findings.append(
                    AttackSurfaceFinding(
                        asset=fqdn,
                        asset_type="dns",
                        issue=f"Dangling CNAME — points to unclaimed {service} resource",
                        severity="critical",
                        details={
                            "cname_target": cname,
                            "service": service,
                        },
                    )
                )

        # ── TLS check ────────────────────────────────────────────────────────
        async with semaphore:
            tls = await loop.run_in_executor(None, check_tls, fqdn)

        if tls.get("error") and not tls.get("cn"):
            # Could not connect at all — skip TLS findings but note it
            if "refused" not in str(tls.get("error", "")).lower():
                local_findings.append(
                    AttackSurfaceFinding(
                        asset=fqdn,
                        asset_type="tls",
                        issue="TLS connection failed",
                        severity="info",
                        details={"error": tls.get("error")},
                    )
                )
            return local_findings

        if tls.get("expired"):
            local_findings.append(
                AttackSurfaceFinding(
                    asset=fqdn,
                    asset_type="tls",
                    issue="TLS certificate is expired",
                    severity="high",
                    details={
                        "days_until_expiry": tls.get("days_until_expiry"),
                        "cn": tls.get("cn"),
                        "san": tls.get("san"),
                    },
                )
            )
        elif (
            tls.get("days_until_expiry") is not None
            and tls["days_until_expiry"] < 30
        ):
            local_findings.append(
                AttackSurfaceFinding(
                    asset=fqdn,
                    asset_type="tls",
                    issue=f"TLS certificate expiring soon ({tls['days_until_expiry']} days)",
                    severity="medium",
                    details={
                        "days_until_expiry": tls["days_until_expiry"],
                        "cn": tls.get("cn"),
                        "san": tls.get("san"),
                    },
                )
            )

        if tls.get("mismatch"):
            local_findings.append(
                AttackSurfaceFinding(
                    asset=fqdn,
                    asset_type="tls",
                    issue="TLS certificate hostname mismatch",
                    severity="high",
                    details={
                        "fqdn": fqdn,
                        "cn": tls.get("cn"),
                        "san": tls.get("san"),
                    },
                )
            )

        return local_findings

    batch_results = await asyncio.gather(
        *[_tls_and_dangling(r) for r in live_results],
        return_exceptions=False,
    )

    for batch in batch_results:
        findings.extend(batch)

    logger.info(
        "Surface scan complete: %d findings (%d live hosts)",
        len(findings),
        len(live_results),
    )
    return findings
