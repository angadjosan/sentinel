"""Shared Pydantic models for all Sentinel modules."""
from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


Severity = Literal["critical", "high", "medium", "low", "info"]


class DepFinding(BaseModel):
    package: str
    version: str
    ecosystem: str  # "pypi" | "npm"
    cve_id: str
    cvss_score: float
    severity: Severity
    summary: str
    fix_version: Optional[str] = None
    aliases: list[str] = Field(default_factory=list)


class CodeSecurityFinding(BaseModel):
    file: str
    line: Optional[int] = None
    category: str  # "access_control" | "injection" | "secrets" | "ssrf" | "crypto" | "idor" | etc.
    severity: Severity
    cwe_id: Optional[str] = None
    explanation: str
    fix_suggestion: Optional[str] = None


class AttackSurfaceFinding(BaseModel):
    asset: str
    asset_type: str  # "subdomain" | "endpoint" | "tls" | "dns"
    issue: str
    severity: Severity
    details: dict = Field(default_factory=dict)


class UnifiedReport(BaseModel):
    scan_id: str = Field(default_factory=lambda: str(uuid4()))
    repo: str
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    dep_findings: list[DepFinding] = Field(default_factory=list)
    code_security_findings: list[CodeSecurityFinding] = Field(default_factory=list)
    attack_surface_findings: list[AttackSurfaceFinding] = Field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return len(self.dep_findings) + len(self.code_security_findings) + len(self.attack_surface_findings)

    @property
    def risk_score(self) -> int:
        """0-100 composite risk score."""
        weights = {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0}
        score = 0
        for f in self.dep_findings:
            score += weights.get(f.severity, 0)
        for f in self.code_security_findings:
            score += weights.get(f.severity, 0) * 2  # code issues weighted higher
        for f in self.attack_surface_findings:
            score += weights.get(f.severity, 0)
        return min(score, 100)
