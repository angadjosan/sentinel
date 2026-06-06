import { ShieldCheck, ShieldOff } from "lucide-react";
import { findingAudit, pullFinding } from "../../../lib/api";
import { SeverityBadge } from "../../../components/SeverityBadge";

export default async function FindingDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const [context, audit] = await Promise.all([pullFinding(id), findingAudit(id)]);
  const finding = context.finding;
  const node = context.node;

  return (
    <>
      <div className="toolbar">
        <div>
          <h1>{finding.title}</h1>
          <div className="muted">{finding.id}</div>
        </div>
        <SeverityBadge severity={finding.severity} />
      </div>

      <section className="grid metrics">
        <div className="panel metric">
          <div className="label">Status</div>
          <div className="value">{finding.status}</div>
        </div>
        <div className="panel metric">
          <div className="label">Type</div>
          <div className="value">{finding.vuln_type}</div>
        </div>
        <div className="panel metric">
          <div className="label">Confirmed</div>
          <div className="value icon-value">{finding.confirmed ? <ShieldCheck size={24} /> : <ShieldOff size={24} />}</div>
        </div>
        <div className="panel metric">
          <div className="label">Fingerprint</div>
          <div className="value compact">{finding.fingerprint}</div>
        </div>
      </section>

      <section className="grid two detail-grid">
        <div className="panel">
          <div className="panel-header">
            <h2>Remediation</h2>
          </div>
          <div className="panel-body">
            <p>{finding.description}</p>
            <ol className="steps">
              {context.remediation_plan.map((step) => (
                <li key={step}>{step}</li>
              ))}
            </ol>
          </div>
        </div>

        <div className="panel">
          <div className="panel-header">
            <h2>Graph Context</h2>
          </div>
          <div className="panel-body">
            {node ? (
              <dl className="kv">
                <dt>Node</dt>
                <dd>{node.id}</dd>
                <dt>Kind</dt>
                <dd>{node.kind}</dd>
                <dt>File</dt>
                <dd>{node.file ?? "n/a"}</dd>
                <dt>Lines</dt>
                <dd>{node.line_start ?? "?"}-{node.line_end ?? "?"}</dd>
                <dt>Entry Point</dt>
                <dd>{node.is_entry_point ? "yes" : "no"}</dd>
                <dt>Sink</dt>
                <dd>{node.is_sink ? "yes" : "no"}</dd>
                <dt>Intent</dt>
                <dd>{node.intent ?? "n/a"}</dd>
              </dl>
            ) : (
              <div className="muted">No graph node linked to this finding.</div>
            )}
          </div>
        </div>
      </section>

      <section className="grid two detail-grid">
        <div className="panel">
          <div className="panel-header">
            <h2>Evidence</h2>
          </div>
          <div className="panel-body">
            <pre className="trace evidence">{finding.evidence ?? "No runtime confirmation evidence recorded."}</pre>
          </div>
        </div>

        <div className="panel">
          <div className="panel-header">
            <h2>Suppression History</h2>
          </div>
          <div className="panel-body">
            {audit.length ? (
              <table className="table compact-table">
                <thead>
                  <tr>
                    <th>Action</th>
                    <th>Reason</th>
                    <th>Time</th>
                  </tr>
                </thead>
                <tbody>
                  {audit.map((row) => (
                    <tr key={row.id}>
                      <td>{row.action}</td>
                      <td>{row.reason}</td>
                      <td>{new Date(row.created_at).toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <div className="muted">No suppression actions recorded.</div>
            )}
          </div>
        </div>
      </section>
    </>
  );
}
