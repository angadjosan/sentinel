"use client"
import { ReactFlow, Background, Controls, MiniMap, type Node, type Edge } from "@xyflow/react"
import "@xyflow/react/dist/style.css"
import type { GraphNode, GraphEdge } from "../lib/api"

// Node colors by kind
const NODE_COLORS: Record<string, string> = {
  ROUTE: "#3b82f6",      // blue
  FUNCTION: "#6b7280",   // gray
  MIDDLEWARE: "#10b981", // green
  PARAMETER: "#f59e0b",  // amber (source)
  FINDING: "#ef4444",    // red (sink/finding)
  FILE: "#8b5cf6",       // purple
  DEPENDENCY: "#ec4899", // pink
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
        <div className="text-xs">
          <div className="font-bold">{n.name}</div>
          <div className="text-gray-300">{n.kind}</div>
          {n.label != null && <div className="italic text-gray-400">{n.label}</div>}
        </div>
      ),
    },
    style: {
      background: NODE_COLORS[n.kind] ?? "#9ca3af",
      color: "white",
      border: n.is_entry_point ? "2px solid white" : "none",
      borderRadius: "8px",
      padding: "8px",
      minWidth: "120px",
    },
  }))

  const flowEdges: Edge[] = edges.map((e) => ({
    id: String(e.id),
    source: e.src,
    target: e.dst,
    label: e.kind,
    style: {
      stroke: e.tainted ? "#ef4444" : e.sanitized ? "#10b981" : "#94a3b8",
      strokeDasharray: e.taint_uncertain ? "5,5" : undefined,
    },
    animated: !!(e.tainted && !e.sanitized),
    labelStyle: { fontSize: 10, fill: "#6b7280" },
  }))

  return (
    <div style={{ width: "100%", height: "400px" }} className="border rounded-lg overflow-hidden">
      <ReactFlow nodes={flowNodes} edges={flowEdges} fitView>
        <Background />
        <Controls />
        <MiniMap />
      </ReactFlow>
    </div>
  )
}
