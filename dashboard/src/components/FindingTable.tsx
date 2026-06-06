"use client";

import { ShieldCheck, Ban } from "lucide-react";
import { useRouter } from "next/navigation";
import { SeverityBadge } from "./SeverityBadge";
import type { Finding } from "../lib/api";
import { suppressFinding } from "../lib/api";

export function FindingTable({ findings }: { findings: Finding[] }) {
  const router = useRouter();

  async function suppress(id: string) {
    await suppressFinding(id, "Reviewed in dashboard");
    router.refresh();
  }

  return (
    <table className="table">
      <thead>
        <tr>
          <th>Severity</th>
          <th>Type</th>
          <th>Finding</th>
          <th>Status</th>
          <th>Confirmed</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        {findings.map((finding) => (
          <tr key={finding.id}>
            <td>
              <SeverityBadge severity={finding.severity} />
            </td>
            <td>{finding.vuln_type}</td>
            <td>
              <strong>{finding.title}</strong>
              <div className="muted">{finding.description}</div>
              <div>{finding.remediation}</div>
            </td>
            <td>{finding.status}</td>
            <td>{finding.confirmed ? <ShieldCheck size={18} color="#0f766e" /> : <span className="muted">no</span>}</td>
            <td>
              <div className="actions">
                <button title="Suppress finding" disabled={finding.status === "suppressed"} onClick={() => suppress(finding.id)}>
                  <Ban size={16} />
                </button>
              </div>
            </td>
          </tr>
        ))}
        {findings.length === 0 ? (
          <tr>
            <td colSpan={6} className="muted">
              No findings recorded.
            </td>
          </tr>
        ) : null}
      </tbody>
    </table>
  );
}
