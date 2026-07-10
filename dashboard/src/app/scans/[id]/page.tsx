import Link from "next/link";
import { ArrowLeft, Radar, GitBranch, Layers } from "lucide-react";
import { getRun, runTrace, traceAccessLog } from "../../../lib/api";
import { cancelRunAction } from "../actions";
import { LiveFindingCards } from "../../../components/LiveFindingCards";
import { StatusPill, relativeTime, fmtDuration } from "../../../components/ui";

export default async function RunDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const run = await getRun(id);
  const [trace, accessLog] = await Promise.all([
    runTrace(id).catch(() => ""),
    traceAccessLog(id).catch(() => [])
  ]);
  const summary = traceSummary(trace);
  const active = canCancel(run.status);

  return (
    <>
      <div className="toolbar">
        <div>
          <Link href="/scans" className="chip" style={{ marginBottom: 10 }}><ArrowLeft size={13} /> Scans</Link>
          <div className="eyebrow">{run.kind}</div>
          <h1 style={{ textTransform: "capitalize" }}>{run.kind} run</h1>
          <div className="sub mono" style={{ fontSize: 12 }}>{run.id}</div>
        </div>
        <div className="toolbar-actions">
          <StatusPill status={run.status} />
          {active ? (
            <form action={cancelRunAction}>
              <input type="hidden" name="runId" value={run.id} />
              <button type="submit" className="danger">Cancel run</button>
            </form>
          ) : null}
        </div>
      </div>

      <section className="panel">
        <div className="statbar" style={{ gridTemplateColumns: "repeat(5, minmax(0,1fr))" }}>
          <Stat label="Findings" value={run.finding_count.toLocaleString()} />
          <Stat label="Tokens" value={run.token_spend.toLocaleString()} />
          <Stat label="Model" value={run.model_used ?? "—"} />
          <Stat label="Duration" value={fmtDuration(run.created_at, run.completed_at)} />
          <Stat label="Started" value={relativeTime(run.created_at)} />
        </div>
      </section>

      {run.status === "running" || run.status === "claimed" ? (
        <LiveFindingCards runId={run.id} apiUrl={process.env.NEXT_PUBLIC_SENTINEL_API_URL ?? "http://localhost:8000"} />
      ) : null}

      <section className="grid two-even" style={{ marginTop: 14 }}>
        <div className="panel">
          <div className="panel-header"><h2>Blast radius</h2><GitBranch size={15} className="dim" /></div>
          <div className="panel-body">
            {summary.graphUpdate ? (
              <dl className="kv">
                <dt>Changed files</dt><dd className="num">{summary.graphUpdate.changed_files}</dd>
                <dt>Affected files</dt><dd className="num">{summary.graphUpdate.blast_radius_files}</dd>
                <dt>Files</dt><dd className="file-ref">{summary.graphUpdate.files.length ? summary.graphUpdate.files.join(", ") : "not recorded"}</dd>
              </dl>
            ) : <div className="empty" style={{ padding: 22 }}><p>No graph-update event recorded for this run.</p></div>}
          </div>
        </div>
        <div className="panel">
          <div className="panel-header"><h2>Adapter coverage</h2><Layers size={15} className="dim" /></div>
          <div className="panel-body">
            {summary.adapterCoverage ? (
              <dl className="kv">
                <dt>Matched</dt><dd className="file-ref">{summary.adapterCoverage.matched_files.length ? summary.adapterCoverage.matched_files.join(", ") : "none"}</dd>
                <dt>Unmatched</dt><dd className="file-ref">{summary.adapterCoverage.unmatched_files.length ? summary.adapterCoverage.unmatched_files.join(", ") : "none"}</dd>
              </dl>
            ) : <div className="empty" style={{ padding: 22 }}><p>No framework-adapter coverage recorded.</p></div>}
          </div>
        </div>
      </section>

      <section className="panel" style={{ marginTop: 14 }}>
        <div className="panel-header">
          <h2>Agent trace</h2>
          <span className="muted">every prompt, tool call, and finding — append-only JSONL</span>
        </div>
        <div className="panel-body">
          <pre className="trace">{trace || "No trace recorded for this run."}</pre>
        </div>
      </section>

      <section className="panel" style={{ marginTop: 14 }}>
        <div className="panel-header">
          <h2>Trace access audit</h2>
          <span className="muted">{accessLog.length} privileged access{accessLog.length === 1 ? "" : "es"} · cannot be deleted</span>
        </div>
        {accessLog.length ? (
          <table className="table compact-table">
            <thead><tr><th>Actor</th><th style={{ textAlign: "right" }}>Accessed</th></tr></thead>
            <tbody>
              {accessLog.map((row) => (
                <tr key={row.id}><td className="mono" style={{ fontSize: 12 }}>{row.actor_id}</td><td className="cell-dim" style={{ textAlign: "right" }}>{relativeTime(row.created_at)}</td></tr>
              ))}
            </tbody>
          </table>
        ) : <div className="empty" style={{ padding: 22 }}><p>No trace access recorded yet.</p></div>}
      </section>
    </>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="stat">
      <div className="stat-label">{label}</div>
      <div className="stat-value" style={{ fontSize: value.length > 12 ? 14 : 20 }}>{value}</div>
    </div>
  );
}

function canCancel(status: string): boolean {
  return ["queued", "claimed", "running"].includes(status);
}

type GraphUpdateEvent = { kind: "graph_update.completed"; changed_files: number; blast_radius_files: number; files: string[] };
type AdapterCoverageEvent = { kind: "adapter.coverage"; matched_files: string[]; unmatched_files: string[] };

function traceSummary(trace: string): { graphUpdate?: GraphUpdateEvent; adapterCoverage?: AdapterCoverageEvent } {
  const summary: { graphUpdate?: GraphUpdateEvent; adapterCoverage?: AdapterCoverageEvent } = {};
  for (const line of trace.split("\n")) {
    if (!line.trim()) continue;
    try {
      const event = JSON.parse(line) as { kind?: string };
      if (event.kind === "graph_update.completed") summary.graphUpdate = event as GraphUpdateEvent;
      if (event.kind === "adapter.coverage") summary.adapterCoverage = event as AdapterCoverageEvent;
    } catch {
      continue;
    }
  }
  return summary;
}
