import Link from "next/link";
import { AlertTriangle, ArrowLeft, Ban, ShieldAlert, ShieldCheck } from "lucide-react";
import { findingAudit, findingGraph, pullFinding } from "../../../lib/api";
import { TaintPathView } from "../../../components/TaintPathView";
import { FindingActions } from "../../../components/FindingActions";
import { SeverityBadge, StatusPill, FileRef, scanFamily, relativeTime } from "../../../components/ui";

export default async function FindingDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const [context, audit, graph] = await Promise.all([
    pullFinding(id),
    findingAudit(id).catch(() => []),
    findingGraph(id).catch(() => ({ nodes: [], edges: [] }))
  ]);
  const finding = context.finding;
  const node = context.node;

  const verdict = finding.confirmed
    ? { cls: "confirmed", icon: <ShieldAlert size={20} />, title: "Confirmed exploitable", sub: "Reproduced by the pentest oracle — a runtime proof exists, not just agent judgment." }
    : finding.status === "suppressed"
    ? { cls: "suppressed", icon: <Ban size={20} />, title: "Suppressed", sub: "Excluded from the queue. Full audit trail preserved below." }
    : finding.status === "suppression_pending"
    ? { cls: "review", icon: <AlertTriangle size={20} />, title: "Suppression pending review", sub: "Awaiting admin approval — still counts as open until approved." }
    : { cls: "review", icon: <AlertTriangle size={20} />, title: "Needs review", sub: "Surfaced by contextual reasoning as reachable and unresolved on this diff." };

  return (
    <>
      <div className="toolbar">
        <div>
          <Link href="/findings" className="chip" style={{ marginBottom: 10 }}><ArrowLeft size={13} /> Findings</Link>
          <div className="eyebrow">{scanFamily(finding.vuln_type)} · {finding.vuln_type.replace(/_/g, " ")}</div>
          <h1>{finding.title}</h1>
          <div className="sub mono" style={{ fontSize: 12 }}>{finding.id}</div>
        </div>
        <div className="toolbar-actions">
          <SeverityBadge severity={finding.severity} />
          <StatusPill status={finding.status} />
        </div>
      </div>

      <div className={`verdict ${verdict.cls}`}>
        <div className="v-icon">{verdict.icon}</div>
        <div style={{ flex: 1 }}>
          <div className="v-title">{verdict.title}</div>
          <div className="v-sub">{verdict.sub}</div>
        </div>
      </div>

      <section className="grid two detail-grid" style={{ marginTop: 14 }}>
        <div className="stack">
          <div className="panel">
            <div className="panel-header"><h2>Exploitability</h2></div>
            <div className="panel-body"><p style={{ margin: 0, lineHeight: 1.6 }}>{finding.description}</p></div>
          </div>
          <div className="panel">
            <div className="panel-header"><h2>Remediation</h2></div>
            <div className="panel-body">
              <ol className="steps">
                {context.remediation_plan.map((step, index) => (<li key={index}>{step}</li>))}
              </ol>
            </div>
          </div>
        </div>

        <div className="stack">
          <div className="panel">
            <div className="panel-header"><h2>Actions</h2></div>
            <div className="panel-body"><FindingActions finding={finding} /></div>
          </div>
          <div className="panel">
            <div className="panel-header"><h2>Location & context</h2></div>
            <div className="panel-body">
              <dl className="kv">
                <dt>File</dt><dd><FileRef file={finding.file} line={finding.line_start} /></dd>
                <dt>Scan</dt><dd>{scanFamily(finding.vuln_type)}</dd>
                <dt>Updated</dt><dd>{relativeTime(finding.updated_at)}</dd>
                {node ? (<>
                  <dt>Graph node</dt><dd className="mono" style={{ fontSize: 12 }}>{node.id}</dd>
                  <dt>Kind</dt><dd>{node.kind}</dd>
                  <dt>Entry point</dt><dd>{node.is_entry_point ? <span className="chip accent">yes</span> : "no"}</dd>
                  <dt>Sink</dt><dd>{node.is_sink ? <span className="chip warn">yes</span> : "no"}</dd>
                  {node.intent ? <><dt>Intent</dt><dd>{node.intent}</dd></> : null}
                </>) : null}
                <dt>Fingerprint</dt><dd className="mono" style={{ fontSize: 11.5 }}>{finding.fingerprint}</dd>
              </dl>
            </div>
          </div>
        </div>
      </section>

      <section className="panel" style={{ marginTop: 14 }}>
        <div className="panel-header">
          <h2>Taint path</h2>
          <span className="muted">{graph.nodes.length} nodes · {graph.edges.length} edges · entry → sink</span>
        </div>
        <div className="panel-body">
          {graph.nodes.length ? <TaintPathView nodes={graph.nodes} edges={graph.edges} focusId={node?.id ?? null} /> : <div className="empty" style={{ padding: 30 }}><p>No graph path recorded for this finding.</p></div>}
        </div>
      </section>

      {finding.confirmed && finding.evidence ? (
        <section className="panel" style={{ marginTop: 14, borderColor: "rgba(255,93,93,0.35)" }}>
          <div className="panel-header" style={{ borderColor: "rgba(255,93,93,0.25)" }}>
            <h2 style={{ color: "var(--critical)", display: "flex", alignItems: "center", gap: 8 }}><ShieldAlert size={16} /> Confirmed exploit evidence</h2>
          </div>
          <div className="panel-body"><pre className="trace evidence" style={{ borderColor: "rgba(255,93,93,0.3)" }}>{finding.evidence}</pre></div>
        </section>
      ) : null}

      <section className={finding.confirmed ? "" : "grid two detail-grid"} style={{ marginTop: 14 }}>
        {finding.confirmed ? null : (
          <div className="panel">
            <div className="panel-header"><h2>Evidence</h2></div>
            <div className="panel-body">
              {finding.evidence ? <pre className="trace evidence">{finding.evidence}</pre> : <div className="empty" style={{ padding: 24 }}><p>No runtime confirmation evidence yet. Run a pentest to attempt exploitation.</p></div>}
            </div>
          </div>
        )}
        <div className="panel">
          <div className="panel-header"><h2>Audit trail</h2><ShieldCheck size={15} className="dim" /></div>
          <div className="panel-body">
            {audit.length ? (
              <div className="stack" style={{ gap: 10 }}>
                {audit.map((row) => (
                  <div key={row.id} className="spread" style={{ borderBottom: "1px solid var(--border)", paddingBottom: 10 }}>
                    <div>
                      <div style={{ textTransform: "capitalize", fontWeight: 550 }}>{row.action}</div>
                      <div className="muted" style={{ fontSize: 12.5 }}>{row.reason}</div>
                    </div>
                    <div className="muted" style={{ fontSize: 12 }}>{relativeTime(row.created_at)}</div>
                  </div>
                ))}
              </div>
            ) : <div className="empty" style={{ padding: 24 }}><p>No suppression actions recorded.</p></div>}
          </div>
        </div>
      </section>
    </>
  );
}
