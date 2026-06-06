import { GitBranch } from "lucide-react";
import { graphSnapshot } from "../../lib/api";

export default async function GraphPage({ searchParams }: { searchParams: Promise<{ q?: string }> }) {
  const [{ q }, graph] = await Promise.all([searchParams, graphSnapshot()]);
  const query = (q ?? "").trim().toLowerCase();
  const nodes = query
    ? graph.nodes.filter((node) => [node.id, node.name, node.kind, node.file, node.intent].some((value) => value?.toLowerCase().includes(query)))
    : graph.nodes;
  const nodeIds = new Set(nodes.map((node) => node.id));
  const edges = graph.edges.filter((edge) => !query || nodeIds.has(edge.src) || nodeIds.has(edge.dst));

  return (
    <>
      <div className="toolbar">
        <div>
          <h1>Graph</h1>
          <div className="muted">{nodes.length} nodes, {edges.length} edges</div>
        </div>
        <form className="search" action="/graph">
          <input name="q" defaultValue={q ?? ""} placeholder="Search nodes" />
          <button type="submit">Search</button>
        </form>
      </div>

      <section className="graph-summary">
        {["ROUTE", "FUNCTION", "FILE", "DEPENDENCY", "MIDDLEWARE"].map((kind) => (
          <div className="panel metric" key={kind}>
            <div className="label">{kind}</div>
            <div className="value">{nodes.filter((node) => node.kind === kind).length}</div>
          </div>
        ))}
      </section>

      <section className="grid two detail-grid">
        <div className="panel">
          <div className="panel-header">
            <h2>Nodes</h2>
          </div>
          <div className="panel-body node-list">
            {nodes.map((node) => (
              <div className={`graph-node ${node.kind.toLowerCase()}`} key={node.id}>
                <div className="node-title">
                  <span>{node.kind}</span>
                  <strong>{node.name}</strong>
                </div>
                <div className="muted">{node.file ?? node.id}</div>
                <div>{node.intent ?? node.label ?? "No semantic label recorded."}</div>
                <div className="node-flags">
                  {node.is_entry_point ? <span>entry</span> : null}
                  {node.auth_required ? <span>auth</span> : null}
                  {node.is_sink ? <span>sink</span> : null}
                </div>
              </div>
            ))}
            {nodes.length === 0 ? <div className="muted">No nodes matched.</div> : null}
          </div>
        </div>

        <div className="panel">
          <div className="panel-header">
            <h2>Edges</h2>
          </div>
          <div className="panel-body edge-list">
            {edges.map((edge) => (
              <div className="edge-row" key={edge.id}>
                <GitBranch size={16} />
                <div>
                  <div><strong>{edge.kind}</strong> {edge.tainted ? "tainted" : edge.sanitized ? "sanitized" : ""}</div>
                  <div className="muted">{edge.src} {"->"} {edge.dst}</div>
                  {edge.call_uncertainty ? <div className="muted">uncertainty: {edge.call_uncertainty}</div> : null}
                </div>
              </div>
            ))}
            {edges.length === 0 ? <div className="muted">No edges matched.</div> : null}
          </div>
        </div>
      </section>
    </>
  );
}
