import { ArrowDown, ShieldAlert, DoorOpen, Crosshair } from "lucide-react";
import type { GraphNode, GraphEdge } from "../lib/api";

function nodeClass(node: GraphNode): string {
  if (node.is_sink) return "sink";
  if (node.is_entry_point) return "entry";
  if (node.kind === "MIDDLEWARE") return "middleware";
  return "";
}

/** Order nodes into a single entry→sink chain for a readable vertical flow. */
function order(nodes: GraphNode[], edges: GraphEdge[], focusId: string | null): GraphNode[] {
  const byId = new Map(nodes.map((node) => [node.id, node]));
  const incoming = new Set(edges.map((edge) => edge.dst));
  const starts = nodes.filter((node) => node.is_entry_point || !incoming.has(node.id));
  const seedOrder = [...starts.map((n) => n.id), focusId ?? "", ...nodes.map((n) => n.id)].filter(Boolean) as string[];
  const ordered: GraphNode[] = [];
  const seen = new Set<string>();
  const queue = [...seedOrder];
  while (queue.length) {
    const id = queue.shift();
    if (!id || seen.has(id) || !byId.has(id)) continue;
    seen.add(id);
    ordered.push(byId.get(id)!);
    for (const edge of edges.filter((e) => e.src === id)) queue.push(edge.dst);
  }
  return ordered;
}

export function FlowPath({ nodes, edges, focusId }: { nodes: GraphNode[]; edges: GraphEdge[]; focusId: string | null }) {
  const byId = new Map(nodes.map((node) => [node.id, node]));
  const ordered = order(nodes, edges, focusId);

  return (
    <div className="flow">
      {ordered.map((node, index) => {
        const next = ordered[index + 1];
        const edge = next ? edges.find((e) => e.src === node.id && e.dst === next.id) : undefined;
        return (
          <div key={node.id}>
            <div className={`flow-node ${nodeClass(node)}${node.id === focusId ? " focus" : ""}`}>
              <div className="fn-head">
                {node.is_entry_point ? <DoorOpen size={14} className="dim" /> : node.is_sink ? <Crosshair size={14} style={{ color: "var(--critical)" }} /> : null}
                <strong>{node.name}</strong>
                <span className="fn-kind">{node.kind}</span>
                {node.is_entry_point ? <span className="node-flags"><span className="entry">entry</span></span> : null}
                {node.is_sink ? <span className="node-flags"><span className="sink">sink</span></span> : null}
                {node.auth_required ? <span className="node-flags"><span className="auth">auth</span></span> : null}
              </div>
              <div className="file-ref">{node.file ? `${node.file}${node.line_start ? `:${node.line_start}` : ""}` : node.id}</div>
              {node.intent || node.label ? <div className="dim" style={{ fontSize: 12.5 }}>{node.intent ?? node.label}</div> : null}
            </div>
            {next ? (
              <div className="flow-connector">
                <ArrowDown size={15} />
                {edge ? (
                  <span className={`edge-tag ${edge.tainted ? "tainted" : edge.sanitized ? "sanitized" : ""}`}>
                    {edge.tainted ? <ShieldAlert size={11} /> : null}
                    {edge.kind}
                    {edge.tainted ? " · tainted" : edge.sanitized ? " · sanitized" : ""}
                    {edge.taint_uncertain ? " · uncertain" : ""}
                    {edge.call_uncertainty ? ` · ${edge.call_uncertainty}` : ""}
                  </span>
                ) : (
                  <span className="edge-tag">related</span>
                )}
              </div>
            ) : null}
          </div>
        );
      })}
      {ordered.length === 0 ? <div className="muted">No path nodes to display.</div> : null}
    </div>
  );
}
