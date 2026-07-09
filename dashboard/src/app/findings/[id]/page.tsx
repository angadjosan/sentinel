import { ShieldCheck, ShieldOff, AlertTriangle } from "lucide-react";
import { findingAudit, findingGraph, pullFinding } from "../../../lib/api";
import { SeverityBadge } from "../../../components/SeverityBadge";
import { TaintPathGraph } from "../../../components/TaintPathGraph";

export default async function FindingDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const [context, audit, graph] = await Promise.all([pullFinding(id), findingAudit(id), findingGraph(id)]);
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

      <section className="panel" style={{ marginTop: 16 }}>
        <div className="panel-header">
          <h2>Taint Path</h2>
          <span className="muted">{graph.nodes.length} nodes, {graph.edges.length} edges</span>
        </div>
        <div className="panel-body">
          {graph.nodes.length ? (
            <TaintPathGraph nodes={graph.nodes} edges={graph.edges} />
          ) : (
            <div className="muted">No graph path recorded for this finding.</div>
          )}
        </div>
      </section>

      {finding.confirmed && finding.evidence && (
        <section className="panel" style={{ marginTop: 16, borderLeft: "4px solid #ef4444" }}>
          <div className="panel-header" style={{ color: "#ef4444" }}>
            <AlertTriangle size={18} style={{ marginRight: 8 }} />
            <h2 style={{ color: "#ef4444" }}>Confirmed Exploit Evidence</h2>
          </div>
          <div className="panel-body">
            <pre className="trace evidence" style={{ borderColor: "#ef4444" }}>{finding.evidence}</pre>
          </div>
        </section>
      )}

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

// NOTE: The bespoke FindingGraph / EdgeLabel / orderNodes / nodeClass renderer
// was removed. The Taint Path panel above now renders via the shared
// <TaintPathGraph /> component; this dead duplicate was never mounted.
