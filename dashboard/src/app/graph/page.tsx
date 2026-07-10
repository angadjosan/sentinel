import Link from "next/link";
import { ArrowRight, DoorOpen, Crosshair, ShieldAlert, HelpCircle, GitBranch, Layers } from "lucide-react";
import { graphSnapshot, listGraphs, type GraphNode, type GraphMeta } from "../../lib/api";
import { GraphExplorer } from "../../components/GraphExplorer";
import { getSelectedRepo } from "../../lib/repo";

const KINDS = [
  { key: "ROUTE", color: "var(--low)" },
  { key: "MIDDLEWARE", color: "var(--accent)" },
  { key: "FUNCTION", color: "var(--muted)" },
  { key: "DEPENDENCY", color: "var(--high)" },
  { key: "FILE", color: "var(--info)" }
];

export default async function GraphPage({ searchParams }: { searchParams: Promise<{ q?: string; view?: string; branch?: string }> }) {
  const { q, view, branch } = await searchParams;
  const selectedRepo = await getSelectedRepo();
  const graphKind = branch ? "branch" : "main";
  const [graph, branches] = await Promise.all([
    graphSnapshot(500, { repoName: selectedRepo, graphKind, branchName: branch }).catch(() => ({ nodes: [], edges: [] })),
    selectedRepo ? listGraphs(selectedRepo).catch(() => [] as GraphMeta[]) : Promise.resolve([] as GraphMeta[])
  ]);
  const query = (q ?? "").trim().toLowerCase();
  const nodes = query
    ? graph.nodes.filter((node) => [node.id, node.name, node.kind, node.file, node.intent].some((value) => value?.toLowerCase().includes(query)))
    : graph.nodes;
  const nodeIds = new Set(nodes.map((node) => node.id));
  const edges = graph.edges.filter((edge) => !query || nodeIds.has(edge.src) || nodeIds.has(edge.dst));
  const showFlow = view !== "list";

  const entryPoints = nodes.filter((n) => n.is_entry_point);
  const sinks = nodes.filter((n) => n.is_sink);
  const tainted = edges.filter((e) => e.tainted).length;
  const confirmed = edges.filter((e) => e.kind === "CONFIRMED_EXPLOIT").length;
  const uncertain = edges.filter((e) => e.taint_uncertain || e.call_uncertainty).length;

  const linkFor = (patch: Record<string, string | undefined>) => {
    const next = { q, view, branch, ...patch };
    const params = new URLSearchParams();
    if (next.q) params.set("q", next.q);
    if (next.view) params.set("view", next.view);
    if (next.branch) params.set("branch", next.branch);
    const s = params.toString();
    return `/graph${s ? `?${s}` : ""}`;
  };

  return (
    <>
      <div className="toolbar">
        <div>
          <div className="eyebrow">Attack surface</div>
          <h1>Graph</h1>
          <div className="sub">
            {nodes.length} nodes · {edges.length} edges — entry points, sinks, and the tainted paths between them
            {selectedRepo ? <> · <span className="mono">{branch ? `branch: ${branch}` : "main"}</span></> : null}
          </div>
        </div>
        <div className="toolbar-actions">
          {selectedRepo ? (
            <BranchSelector branches={branches} current={branch} linkFor={linkFor} />
          ) : (
            <span className="chip warn" title="Showing the main graph of every repo in the account — select a repo to view a single branch"><Layers size={12} /> all repos · main</span>
          )}
          <form action="/graph" className="search">
            <input name="q" defaultValue={q ?? ""} placeholder="Search nodes…" style={{ minWidth: 220 }} />
            {view ? <input type="hidden" name="view" value={view} /> : null}
          </form>
          <Link href={linkFor({ view: showFlow ? "list" : undefined })} className="chip">{showFlow ? "List view" : "Flow view"}</Link>
        </div>
      </div>

      <section className="panel" style={{ marginBottom: 14 }}>
        <div className="statbar" style={{ gridTemplateColumns: "repeat(5, minmax(0,1fr))" }}>
          <SurfaceStat icon={<DoorOpen size={13} />} label="Entry points" value={entryPoints.length} />
          <SurfaceStat icon={<Crosshair size={13} />} label="Sinks" value={sinks.length} />
          <SurfaceStat icon={<ShieldAlert size={13} />} label="Tainted flows" value={tainted} tone="crit" />
          <SurfaceStat icon={<ShieldAlert size={13} />} label="Confirmed exploits" value={confirmed} tone="crit" />
          <SurfaceStat icon={<HelpCircle size={13} />} label="Uncertain edges" value={uncertain} tone="warn" />
        </div>
      </section>

      <div className="wrap" style={{ marginBottom: 14, alignItems: "center" }}>
        <span className="muted" style={{ fontSize: 12 }}>Node kinds:</span>
        {KINDS.map((kind) => (
          <span key={kind.key} className="chip"><span style={{ width: 8, height: 8, borderRadius: 2, background: kind.color, display: "inline-block" }} /> {kind.key.toLowerCase()} · {nodes.filter((n) => n.kind === kind.key).length}</span>
        ))}
      </div>

      {nodes.length === 0 ? (
        <div className="panel"><div className="empty" style={{ padding: 54 }}><div className="empty-icon"><GitBranch size={22} /></div><h3>No graph yet</h3><p>Run <code>sentinel init</code> to build the code graph. It maps routes, functions, sinks and the data-flow edges between them — pointers and labels only, never source.</p></div></div>
      ) : showFlow ? (
        <section className="panel">
          <div className="panel-header"><h2>Interactive graph</h2><span className="muted">drag to pan · scroll to zoom · click a node</span></div>
          <div className="panel-body" style={{ padding: 0 }}><GraphExplorer nodes={nodes} edges={edges} /></div>
        </section>
      ) : (
        <ListView nodes={nodes} edges={edges} entryPoints={entryPoints} sinks={sinks} />
      )}
    </>
  );
}

function BranchSelector({ branches, current, linkFor }: { branches: GraphMeta[]; current?: string; linkFor: (patch: Record<string, string | undefined>) => string; }) {
  const branchGraphs = branches.filter((g) => g.kind === "branch" && g.branch_name);
  return (
    <div className="wrap" style={{ gap: 6, alignItems: "center" }}>
      <GitBranch size={12} className="muted" />
      <Link href={linkFor({ branch: undefined })} className={`chip ${current ? "" : "active"}`}>main</Link>
      {branchGraphs.map((g) => (
        <Link key={g.id} href={linkFor({ branch: g.branch_name! })} className={`chip ${current === g.branch_name ? "active" : ""}`} title={`branch graph · ${g.branch_name}`}>
          {g.branch_name}
        </Link>
      ))}
    </div>
  );
}

function SurfaceStat({ icon, label, value, tone }: { icon: React.ReactNode; label: string; value: number; tone?: "crit" | "warn" }) {
  const color = tone === "crit" ? "var(--critical)" : tone === "warn" ? "var(--high)" : "var(--text)";
  return (
    <div className="stat">
      <div className="stat-label">{icon}{label}</div>
      <div className="stat-value" style={{ color: value ? color : "var(--text)" }}>{value}</div>
    </div>
  );
}

function ListView({ nodes, edges, entryPoints, sinks }: { nodes: GraphNode[]; edges: import("../../lib/api").GraphEdge[]; entryPoints: GraphNode[]; sinks: GraphNode[] }) {
  return (
    <section className="grid two-even">
      <div className="panel">
        <div className="panel-header"><h2>Entry points → sinks</h2><span className="muted">{entryPoints.length} entries · {sinks.length} sinks</span></div>
        <div className="panel-body node-list">
          {[...entryPoints, ...sinks, ...nodes.filter((n) => !n.is_entry_point && !n.is_sink)].slice(0, 60).map((node) => (
            <NodeCard key={node.id} node={node} />
          ))}
        </div>
      </div>
      <div className="panel">
        <div className="panel-header"><h2>Edges</h2><span className="muted">{edges.length}</span></div>
        <div className="panel-body edge-list">
          {edges.slice(0, 80).map((edge) => {
            const attrs = [edge.tainted ? "tainted" : null, edge.sanitized ? "sanitized" : null, edge.taint_uncertain ? "uncertain" : null, edge.call_uncertainty].filter(Boolean);
            return (
              <div className="edge-row" key={edge.id}>
                <ArrowRight size={14} />
                <div style={{ minWidth: 0 }}>
                  <div className="wrap" style={{ gap: 6, alignItems: "center" }}>
                    <span className={`chip ${edge.tainted ? "warn" : edge.kind === "CONFIRMED_EXPLOIT" ? "warn" : ""}`}>{edge.kind}</span>
                    {attrs.length ? <span className="muted" style={{ fontSize: 11.5 }}>{attrs.join(" · ")}</span> : null}
                  </div>
                  <div className="file-ref" style={{ fontSize: 11, marginTop: 4 }}>{edge.src} → {edge.dst}</div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}

function NodeCard({ node }: { node: GraphNode }) {
  return (
    <div className={`graph-node ${node.is_sink ? "sink" : node.kind.toLowerCase()}`}>
      <div className="node-title">
        <span>{node.kind}</span>
        <strong>{node.name}</strong>
      </div>
      <div className="file-ref">{node.file ?? node.id}</div>
      {node.intent || node.label ? <div className="dim" style={{ fontSize: 12.5 }}>{node.intent ?? node.label}</div> : null}
      {node.is_entry_point || node.is_sink || node.auth_required ? (
        <div className="node-flags">
          {node.is_entry_point ? <span className="entry">entry</span> : null}
          {node.is_sink ? <span className="sink">sink</span> : null}
          {node.auth_required ? <span className="auth">auth</span> : null}
        </div>
      ) : null}
    </div>
  );
}
