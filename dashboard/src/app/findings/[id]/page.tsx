import { ShieldCheck, ShieldOff } from "lucide-react";
import { findingAudit, findingGraph, pullFinding, type GraphEdge, type GraphNode } from "../../../lib/api";
import { SeverityBadge } from "../../../components/SeverityBadge";

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
          {graph.nodes.length ? <FindingGraph nodes={graph.nodes} edges={graph.edges} focusId={node?.id ?? null} /> : <div className="muted">No graph path recorded for this finding.</div>}
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

function FindingGraph({ nodes, edges, focusId }: { nodes: GraphNode[]; edges: GraphEdge[]; focusId: string | null }) {
  const byId = new Map(nodes.map((node) => [node.id, node]));
  const ordered = orderNodes(nodes, edges, focusId);
  return (
    <div className="finding-graph">
      {ordered.map((node, index) => {
        const outgoing = edges.filter((edge) => edge.src === node.id && byId.has(edge.dst));
        return (
          <div className="finding-graph-step" key={node.id}>
            <div className={`finding-graph-node ${nodeClass(node)}${node.id === focusId ? " focus" : ""}`}>
              <div className="node-title">
                <span>{node.kind}</span>
                <strong>{node.name}</strong>
              </div>
              <div className="muted">{node.file ? `${node.file}${node.line_start ? `:${node.line_start}` : ""}` : node.id}</div>
              <div>{node.intent ?? node.label ?? "No semantic label recorded."}</div>
              <div className="node-flags">
                {node.is_entry_point ? <span>entry</span> : null}
                {node.auth_required ? <span>auth</span> : null}
                {node.is_sink ? <span>sink</span> : null}
              </div>
            </div>
            {index < ordered.length - 1 ? (
              <div className="finding-graph-edges">
                {outgoing.length ? outgoing.map((edge) => <EdgeLabel edge={edge} dst={byId.get(edge.dst)} key={edge.id} />) : <span className="muted">related</span>}
              </div>
            ) : null}
          </div>
        );
      })}
    </div>
  );
}

function EdgeLabel({ edge, dst }: { edge: GraphEdge; dst: GraphNode | undefined }) {
  const attrs = [edge.tainted ? "tainted" : null, edge.sanitized ? "sanitized" : null, edge.taint_uncertain ? "uncertain" : null, edge.call_uncertainty].filter(Boolean);
  return (
    <div className={`finding-graph-edge ${edge.kind.toLowerCase()}`}>
      <span>{edge.kind}</span>
      {attrs.length ? <small>{attrs.join(", ")}</small> : null}
      {dst ? <small>{dst.name}</small> : null}
    </div>
  );
}

function orderNodes(nodes: GraphNode[], edges: GraphEdge[], focusId: string | null): GraphNode[] {
  const byId = new Map(nodes.map((node) => [node.id, node]));
  const incoming = new Set(edges.map((edge) => edge.dst));
  const starts = nodes.filter((node) => !incoming.has(node.id));
  const focusNode = focusId ? byId.get(focusId) : undefined;
  const start = focusNode ?? starts[0] ?? nodes[0];
  if (!start) return [];
  const ordered: GraphNode[] = [];
  const seen = new Set<string>();
  const queue = [start.id, ...starts.map((node) => node.id), ...nodes.map((node) => node.id)];
  while (queue.length) {
    const id = queue.shift();
    if (!id || seen.has(id)) continue;
    const node = byId.get(id);
    if (!node) continue;
    seen.add(id);
    ordered.push(node);
    for (const edge of edges.filter((candidate) => candidate.src === id)) queue.push(edge.dst);
  }
  return ordered;
}

function nodeClass(node: GraphNode): string {
  if (node.is_sink) return "sink";
  return node.kind.toLowerCase();
}
