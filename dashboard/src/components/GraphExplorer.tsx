"use client"

import { useCallback, useState } from "react"
import { ReactFlow, Background, Controls, MiniMap, type Node, type Edge, type NodeMouseHandler } from "@xyflow/react"
import "@xyflow/react/dist/style.css"
import type { GraphNode, GraphEdge } from "../lib/api"

const NODE_COLORS: Record<string, string> = {
  ROUTE: "#3b82f6",
  FUNCTION: "#6b7280",
  MIDDLEWARE: "#10b981",
  PARAMETER: "#f59e0b",
  FINDING: "#ef4444",
  FILE: "#8b5cf6",
  DEPENDENCY: "#ec4899",
  CLASS: "#0ea5e9",
}

interface GraphExplorerProps {
  nodes: GraphNode[]
  edges: GraphEdge[]
}

const MAX_NODES = 200

function layoutNodes(nodes: GraphNode[], edges: GraphEdge[]): Node[] {
  const byId = new Map(nodes.map((n) => [n.id, n]))
  const inDegree = new Map(nodes.map((n) => [n.id, 0]))
  for (const e of edges) {
    inDegree.set(e.dst, (inDegree.get(e.dst) ?? 0) + 1)
  }
  const roots = nodes.filter((n) => (inDegree.get(n.id) ?? 0) === 0)
  const positioned = new Map<string, { x: number; y: number }>()
  const colWidth = 250
  const rowHeight = 120
  let col = 0

  const visit = (id: string, depth: number) => {
    if (positioned.has(id)) return
    const existing = [...positioned.values()]
    const sameDepth = existing.filter((_, i) => [...positioned.keys()][i] && depth === Math.floor([...positioned.values()][i].x / colWidth))
    positioned.set(id, { x: depth * colWidth, y: sameDepth.length * rowHeight })
    const outgoing = edges.filter((e) => e.src === id).map((e) => e.dst)
    for (const dst of outgoing) visit(dst, depth + 1)
  }

  for (const r of roots) visit(r.id, col++)
  for (const n of nodes) {
    if (!positioned.has(n.id)) {
      const existing = [...positioned.values()]
      positioned.set(n.id, { x: col * colWidth, y: existing.length * rowHeight })
    }
  }

  return nodes.map((n) => {
    const pos = positioned.get(n.id) ?? { x: 0, y: 0 }
    return {
      id: n.id,
      position: pos,
      data: {
        label: (
          <div style={{ fontSize: 11, maxWidth: 180 }}>
            <div style={{ fontWeight: 700, fontSize: 10, opacity: 0.7 }}>{n.kind}</div>
            <div style={{ fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{n.name}</div>
            {n.label && <div style={{ opacity: 0.75, fontSize: 10 }}>{n.label}</div>}
            {n.file && <div style={{ opacity: 0.5, fontSize: 9 }}>{n.file.split("/").slice(-2).join("/")}</div>}
          </div>
        ),
        raw: n,
      },
      style: {
        background: NODE_COLORS[n.kind] ?? "#9ca3af",
        color: "white",
        border: n.is_entry_point ? "2px solid white" : n.is_sink ? "2px solid #fbbf24" : "none",
        borderRadius: 8,
        padding: "6px 10px",
        minWidth: 140,
      },
    }
  })
}

export function GraphExplorer({ nodes: rawNodes, edges: rawEdges }: GraphExplorerProps) {
  const sliced = rawNodes.slice(0, MAX_NODES)
  const slicedIds = new Set(sliced.map((n) => n.id))
  const slicedEdges = rawEdges.filter((e) => slicedIds.has(e.src) && slicedIds.has(e.dst))

  const flowNodes = layoutNodes(sliced, slicedEdges)
  const flowEdges: Edge[] = slicedEdges.map((e) => ({
    id: String(e.id),
    source: e.src,
    target: e.dst,
    label: e.kind,
    style: {
      stroke: e.tainted ? "#ef4444" : e.sanitized ? "#10b981" : "#94a3b8",
      strokeDasharray: e.taint_uncertain ? "5,5" : undefined,
    },
    animated: !!(e.tainted && !e.sanitized),
    labelStyle: { fontSize: 9, fill: "#6b7280" },
  }))

  const [selected, setSelected] = useState<GraphNode | null>(null)

  const onNodeClick: NodeMouseHandler = useCallback((_event, node) => {
    setSelected((node.data as { raw: GraphNode }).raw)
  }, [])

  return (
    <div style={{ display: "flex", height: 600 }}>
      <div style={{ flex: 1, position: "relative" }}>
        {rawNodes.length > MAX_NODES && (
          <div style={{ position: "absolute", top: 8, left: 8, zIndex: 10, background: "#1e293b", color: "#f59e0b", padding: "4px 10px", borderRadius: 6, fontSize: 12 }}>
            Showing {MAX_NODES} of {rawNodes.length} nodes — search to filter
          </div>
        )}
        <ReactFlow
          nodes={flowNodes}
          edges={flowEdges}
          onNodeClick={onNodeClick}
          fitView
          fitViewOptions={{ padding: 0.2 }}
        >
          <Background />
          <Controls />
          <MiniMap
            nodeColor={(n) => {
              const raw = (n.data as { raw?: GraphNode })?.raw
              return NODE_COLORS[raw?.kind ?? ""] ?? "#9ca3af"
            }}
            style={{ background: "#0f172a" }}
          />
        </ReactFlow>
      </div>
      {selected && (
        <div style={{ width: 280, borderLeft: "1px solid #1e293b", overflowY: "auto", padding: 16, background: "#0f172a" }}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 12 }}>
            <strong style={{ fontSize: 14 }}>Node Detail</strong>
            <button onClick={() => setSelected(null)} style={{ background: "none", border: "none", cursor: "pointer", color: "#94a3b8" }}>✕</button>
          </div>
          <dl className="kv" style={{ fontSize: 12 }}>
            <dt>Kind</dt><dd>{selected.kind}</dd>
            <dt>Name</dt><dd style={{ wordBreak: "break-all" }}>{selected.name}</dd>
            {selected.file && <><dt>File</dt><dd style={{ wordBreak: "break-all" }}>{selected.file}{selected.line_start ? `:${selected.line_start}` : ""}</dd></>}
            {selected.label && <><dt>Label</dt><dd>{selected.label}</dd></>}
            {selected.intent && <><dt>Intent</dt><dd>{selected.intent}</dd></>}
            {selected.trust_level && <><dt>Trust</dt><dd>{selected.trust_level}</dd></>}
            <dt>Entry Point</dt><dd>{selected.is_entry_point ? "yes" : "no"}</dd>
            <dt>Auth Required</dt><dd>{selected.auth_required ? "yes" : "no"}</dd>
            <dt>Sink</dt><dd>{selected.is_sink ? "yes" : "no"}</dd>
            {selected.is_new && <><dt>Changed</dt><dd style={{ color: "#f59e0b" }}>this diff</dd></>}
          </dl>
        </div>
      )}
    </div>
  )
}
