"use client";

import { useState } from "react";
import { ListTree, Waypoints } from "lucide-react";
import { FlowPath } from "./FlowPath";
import { TaintPathGraph } from "./TaintPathGraph";
import type { GraphNode, GraphEdge } from "../lib/api";

export function TaintPathView({ nodes, edges, focusId }: { nodes: GraphNode[]; edges: GraphEdge[]; focusId: string | null }) {
  const [view, setView] = useState<"flow" | "graph">("flow");
  return (
    <div>
      <div className="wrap" style={{ justifyContent: "flex-end", marginBottom: 12 }}>
        <div className="seg">
          <button className={view === "flow" ? "active" : ""} onClick={() => setView("flow")}><ListTree size={13} /> Flow</button>
          <button className={view === "graph" ? "active" : ""} onClick={() => setView("graph")}><Waypoints size={13} /> Graph</button>
        </div>
      </div>
      {view === "flow" ? <FlowPath nodes={nodes} edges={edges} focusId={focusId} /> : <TaintPathGraph nodes={nodes} edges={edges} />}
    </div>
  );
}
