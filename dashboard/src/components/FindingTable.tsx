"use client";

import { ShieldCheck, Ban, Check, X } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { SeverityBadge } from "./SeverityBadge";
import type { Finding } from "../lib/api";
import { approveSuppressionAction, rejectSuppressionAction, suppressFindingAction } from "../app/findings/actions";

export function FindingTable({ findings }: { findings: Finding[] }) {
  const router = useRouter();

  // Prompt for a reason (parity with the CLI's required `--reason`) instead of
  // writing a hardcoded string. The API enforces a minimum-length reason.
  function promptReason(verb: string): string | null {
    const reason = window.prompt(`Reason for ${verb} (required):`);
    if (reason === null) return null; // cancelled
    const trimmed = reason.trim();
    if (trimmed.length < 10) {
      window.alert("A reason of at least 10 characters is required.");
      return null;
    }
    return trimmed;
  }

  async function suppress(id: string) {
    const reason = promptReason("suppressing this finding");
    if (reason === null) return;
    await suppressFindingAction(id, reason);
    router.refresh();
  }

  async function approve(id: string) {
    const reason = promptReason("approving this suppression");
    if (reason === null) return;
    await approveSuppressionAction(id, reason);
    router.refresh();
  }

  async function reject(id: string) {
    const reason = promptReason("rejecting this suppression");
    if (reason === null) return;
    await rejectSuppressionAction(id, reason);
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
