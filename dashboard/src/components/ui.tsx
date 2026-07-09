import type { Finding } from "../lib/api";

/** Map a vuln_type to the scan family that surfaces it (README: SAST / SCA / Secret). */
export function scanFamily(vulnType: string): "SAST" | "SCA" | "Secret" | "Pentest" {
  const t = vulnType.toLowerCase();
  if (t.includes("dependency") || t.includes("cve")) return "SCA";
  if (t.includes("secret") || t.includes("hardcoded") || t.includes("credential") || t.includes("key")) return "Secret";
  return "SAST";
}

export function StatusPill({ status }: { status: string }) {
  const label = status.replace(/_/g, " ");
  return (
    <span className={`pill ${status}`}>
      <span className="dot" />
      {label}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: Finding["severity"] }) {
  return <span className={`badge ${severity}`}>{severity}</span>;
}

export function SevDot({ severity }: { severity: Finding["severity"] }) {
  return <span className={`sev-dot ${severity}`} title={severity} />;
}

export function FileRef({ file, line }: { file: string | null; line?: number | null }) {
  if (!file) return <span className="muted">—</span>;
  return <span className="file-ref">{file}{line ? `:${line}` : ""}</span>;
}

const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
export function bySeverity(a: Finding, b: Finding): number {
  return (SEV_RANK[a.severity] ?? 5) - (SEV_RANK[b.severity] ?? 5);
}

export function relativeTime(iso: string): string {
  const then = new Date(iso).getTime();
  const secs = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (secs < 60) return "just now";
  const mins = Math.round(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.round(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.round(hours / 24);
  if (days < 30) return `${days}d ago`;
  return new Date(iso).toLocaleDateString();
}

export function fmtDuration(startIso: string, endIso: string | null): string {
  if (!endIso) return "—";
  const secs = Math.max(0, Math.round((new Date(endIso).getTime() - new Date(startIso).getTime()) / 1000));
  if (secs < 60) return `${secs}s`;
  const mins = Math.floor(secs / 60);
  return `${mins}m ${secs % 60}s`;
}
