"use client"
import { ReactFlow, Background, Controls, MiniMap, type Node, type Edge } from "@xyflow/react"
import "@xyflow/react/dist/style.css"
import type { GraphNode, GraphEdge } from "../lib/api"

// Node colors by kind — aligned with the design tokens
const NODE_COLORS: Record<string, string> = {
  ROUTE: "#5ea8ff",
  FUNCTION: "#2b3a33",
  MIDDLEWARE: "#2dd482",
  PARAMETER: "#ffd15c",
  FINDING: "#ff5d5d",
  FILE: "#8b93a7",
  DEPENDENCY: "#ff9e4f",
}

interface TaintPathGraphProps {
  nodes: GraphNode[]
  edges: GraphEdge[]
}

export function TaintPathGraph({ nodes, edges }: TaintPathGraphProps) {
  const flowNodes: Node[] = nodes.map((n, i) => ({
    id: n.id,
    position: { x: (i % 4) * 220, y: Math.floor(i / 4) * 130 },
    data: {
      label: (
        <div style={{ fontSize: 12, maxWidth: 170 }}>
          <div style={{ fontWeight: 700, fontSize: 9.5, opacity: 0.7, letterSpacing: "0.04em" }}>{n.kind}</div>
          <div style={{ fontWeight: 650, fontSize: 12.5 }}>{n.name}</div>
          {n.label != null && <div style={{ opacity: 0.8, fontSize: 10.5 }}>{n.label}</div>}
        </div>
      ),
    },
    style: {
      background: NODE_COLORS[n.kind] ?? "#2b3a33",
      color: n.kind === "PARAMETER" || n.kind === "MIDDLEWARE" ? "#04150c" : "#e8efe9",
      border: n.is_entry_point ? "2px solid #e8efe9" : n.is_sink ? "2px solid #ff5d5d" : "1px solid rgba(255,255,255,0.08)",
      borderRadius: "8px",
      padding: "8px 10px",
      minWidth: "130px",
    },
  }))

  const flowEdges: Edge[] = edges.map((e) => ({
    id: String(e.id),
    source: e.src,
    target: e.dst,
    label: e.kind,
    style: {
      stroke: e.tainted ? "#ff5d5d" : e.sanitized ? "#2dd482" : "#3a453f",
      strokeDasharray: e.taint_uncertain ? "5,5" : undefined,
    },
    animated: !!(e.tainted && !e.sanitized),
    labelStyle: { fontSize: 10, fill: "#9aa6a0" },
    labelBgStyle: { fill: "#0f1210" },
  }))

  return (
    <div style={{ width: "100%", height: "440px", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", overflow: "hidden" }}>
      <ReactFlow nodes={flowNodes} edges={flowEdges} fitView fitViewOptions={{ padding: 0.3, maxZoom: 1.2 }} minZoom={0.3} proOptions={{ hideAttribution: true }}>
        <Background />
        <Controls />
        <MiniMap />
      </ReactFlow>
    </div>
  )
}
