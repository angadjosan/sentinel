import { GitBranch } from "lucide-react";
import { graphSnapshot } from "../../lib/api";
import { GraphExplorer } from "../../components/GraphExplorer";

export default async function GraphPage({ searchParams }: { searchParams: Promise<{ q?: string; view?: string }> }) {
  const [{ q, view }, graph] = await Promise.all([searchParams, graphSnapshot()]);
  const query = (q ?? "").trim().toLowerCase();
  const nodes = query
    ? graph.nodes.filter((node) => [node.id, node.name, node.kind, node.file, node.intent].some((value) => value?.toLowerCase().includes(query)))
    : graph.nodes;
  const nodeIds = new Set(nodes.map((node) => node.id));
  const edges = graph.edges.filter((edge) => !query || nodeIds.has(edge.src) || nodeIds.has(edge.dst));
  const showFlow = view === "flow";

  return (
    <>
      <div className="toolbar">
        <div>
          <h1>Graph</h1>
          <div className="muted">{nodes.length} nodes, {edges.length} edges</div>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <form className="search" action="/graph">
            <input name="q" defaultValue={q ?? ""} placeholder="Search nodes" />
            {view && <input type="hidden" name="view" value={view} />}
            <button type="submit">Search</button>
          </form>
          <form action="/graph">
            {q && <input type="hidden" name="q" value={q} />}
            <input type="hidden" name="view" value={showFlow ? "list" : "flow"} />
            <button type="submit" className={showFlow ? "" : "primary"} style={{ fontSize: 13 }}>
              {showFlow ? "List view" : "Flow view"}
            </button>
          </form>
        </div>
      </div>

      <section className="graph-summary">
        {["ROUTE", "FUNCTION", "FILE", "DEPENDENCY", "MIDDLEWARE"].map((kind) => (
          <div className="panel metric" key={kind}>
            <div className="label">{kind}</div>
            <div className="value">{nodes.filter((node) => node.kind === kind).length}</div>
          </div>
        ))}
      </section>

      {showFlow ? (
        <section className="panel" style={{ marginTop: 16 }}>
          <div className="panel-header">
            <h2>Interactive Graph</h2>
            <span className="muted">Drag to pan · scroll to zoom · click node to inspect</span>
          </div>
          <div className="panel-body" style={{ padding: 0 }}>
            <GraphExplorer nodes={nodes} edges={edges} />
          </div>
        </section>
      ) : (
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
      )}
    </>
  );
}
