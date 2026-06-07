"use client";

import { ShieldCheck, Ban, Check, X } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { SeverityBadge } from "./SeverityBadge";
import type { Finding } from "../lib/api";
import { approveSuppression, rejectSuppression, suppressFinding } from "../lib/api";

export function FindingTable({ findings }: { findings: Finding[] }) {
  const router = useRouter();

  async function suppress(id: string) {
    await suppressFinding(id, "Reviewed in dashboard");
    router.refresh();
  }

  async function approve(id: string) {
    await approveSuppression(id, "Approved in dashboard");
    router.refresh();
  }

  async function reject(id: string) {
    await rejectSuppression(id, "Rejected in dashboard");
    router.refresh();
  }

  return (
    <table className="table">
      <thead>
        <tr>
          <th>Severity</th>
          <th>Type</th>
          <th>Finding</th>
          <th>File</th>
          <th>Status</th>
          <th>Updated</th>
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
              <Link className="row-link" href={`/findings/${finding.id}`}>
                <strong>{finding.title}</strong>
              </Link>
              <div className="muted">{finding.description}</div>
              <div>{finding.remediation}</div>
            </td>
            <td>{finding.file ? `${finding.file}${finding.line_start ? `:${finding.line_start}` : ""}` : <span className="muted">n/a</span>}</td>
            <td>{finding.status}</td>
            <td>{new Date(finding.updated_at).toLocaleString()}</td>
            <td>{finding.confirmed ? <ShieldCheck size={18} color="#0f766e" /> : <span className="muted">no</span>}</td>
            <td>
              <div className="actions">
                <button title="Suppress finding" disabled={finding.status === "suppressed"} onClick={() => suppress(finding.id)}>
                  <Ban size={16} />
                </button>
                {finding.status === "suppression_pending" ? (
                  <>
                    <button title="Approve suppression" onClick={() => approve(finding.id)}>
                      <Check size={16} />
                    </button>
                    <button title="Reject suppression" onClick={() => reject(finding.id)}>
                      <X size={16} />
                    </button>
                  </>
                ) : null}
              </div>
            </td>
          </tr>
        ))}
        {findings.length === 0 ? (
          <tr>
            <td colSpan={8} className="muted">
              No findings recorded.
            </td>
          </tr>
        ) : null}
      </tbody>
    </table>
  );
}
