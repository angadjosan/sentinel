"""SQLAlchemy models for Sentinel findings persistence."""
from datetime import datetime, timezone
from sqlalchemy import Column, String, Float, Integer, Boolean, DateTime, Text, JSON, ForeignKey
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


class Repo(Base):
    __tablename__ = "repos"
    id = Column(String, primary_key=True)  # "owner/repo"
    github_installation_id = Column(Integer, nullable=True)
    default_branch = Column(String, default="main")
    last_scanned_at = Column(DateTime(timezone=True), nullable=True)
    scans = relationship("Scan", back_populates="repo")


class Scan(Base):
    __tablename__ = "scans"
    id = Column(String, primary_key=True)  # UUID
    repo_id = Column(String, ForeignKey("repos.id"), nullable=False)
    scan_type = Column(String)  # "full" | "deps" | "code" | "surface" | "pr"
    pr_number = Column(Integer, nullable=True)
    head_sha = Column(String, nullable=True)
    status = Column(String, default="pending")  # "pending" | "running" | "complete" | "failed"
    risk_score = Column(Integer, default=0)
    started_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime(timezone=True), nullable=True)
    repo = relationship("Repo", back_populates="scans")
    dep_findings = relationship("DepFindingRow", back_populates="scan")
    code_findings = relationship("CodeFindingRow", back_populates="scan")


class DepFindingRow(Base):
    __tablename__ = "dep_findings"
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)
    package = Column(String, nullable=False)
    version = Column(String)
    ecosystem = Column(String)
    cve_id = Column(String)
    cvss_score = Column(Float)
    severity = Column(String)
    summary = Column(Text)
    fix_version = Column(String, nullable=True)
    scan = relationship("Scan", back_populates="dep_findings")


class CodeFindingRow(Base):
    __tablename__ = "code_findings"
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)
    file = Column(String)
    line = Column(Integer, nullable=True)
    category = Column(String)
    severity = Column(String)
    cwe_id = Column(String, nullable=True)
    explanation = Column(Text)
    fix_suggestion = Column(Text, nullable=True)
    scan = relationship("Scan", back_populates="code_findings")
