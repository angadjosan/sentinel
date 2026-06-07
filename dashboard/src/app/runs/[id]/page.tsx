import { getRun, runTrace, traceAccessLog } from "../../../lib/api";
import { cancelRunAction } from "../actions";

export default async function RunDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const run = await getRun(id);
  const trace = await runTrace(id);
  const accessLog = await traceAccessLog(id);
  const summary = traceSummary(trace);
  return (
    <>
      <div className="toolbar">
        <h1>Run Trace</h1>
        <div className="actions">
          <div className="muted">{run.id}</div>
          {canCancel(run.status) ? (
            <form action={cancelRunAction}>
              <input type="hidden" name="runId" value={run.id} />
              <button type="submit" className="danger">Cancel</button>
            </form>
          ) : null}
        </div>
      </div>
      <section className="grid metrics">
        <div className="panel metric">
          <div className="label">Kind</div>
          <div className="value">{run.kind}</div>
        </div>
        <div className="panel metric">
          <div className="label">Status</div>
          <div className="value">{run.status}</div>
        </div>
        <div className="panel metric">
          <div className="label">Tokens</div>
          <div className="value">{run.token_spend}</div>
        </div>
        <div className="panel metric">
          <div className="label">Findings</div>
          <div className="value">{run.finding_count}</div>
        </div>
      </section>
      <section className="grid metrics" style={{ marginTop: 16 }}>
        <div className="panel metric">
          <div className="label">Model</div>
          <div className="value">{run.model_used ?? "n/a"}</div>
        </div>
        <div className="panel metric">
          <div className="label">Created</div>
          <div className="value compact">{formatDate(run.created_at)}</div>
        </div>
        <div className="panel metric">
          <div className="label">Completed</div>
          <div className="value compact">{run.completed_at ? formatDate(run.completed_at) : "not completed"}</div>
        </div>
      </section>
      <section className="grid two detail-grid">
        <div className="panel">
          <div className="panel-header">
            <h2>Blast Radius</h2>
          </div>
          <div className="panel-body">
            {summary.graphUpdate ? (
              <dl className="kv">
                <dt>Changed Files</dt>
                <dd>{summary.graphUpdate.changed_files}</dd>
                <dt>Affected Files</dt>
                <dd>{summary.graphUpdate.blast_radius_files}</dd>
                <dt>Files</dt>
                <dd>{summary.graphUpdate.files.length ? summary.graphUpdate.files.join(", ") : "not recorded"}</dd>
              </dl>
            ) : (
              <div className="muted">No graph update event recorded.</div>
            )}
          </div>
        </div>
        <div className="panel">
          <div className="panel-header">
            <h2>Adapter Coverage</h2>
          </div>
          <div className="panel-body">
            {summary.adapterCoverage ? (
              <dl className="kv">
                <dt>Matched</dt>
                <dd>{summary.adapterCoverage.matched_files.length ? summary.adapterCoverage.matched_files.join(", ") : "none"}</dd>
                <dt>Unmatched</dt>
                <dd>{summary.adapterCoverage.unmatched_files.length ? summary.adapterCoverage.unmatched_files.join(", ") : "none"}</dd>
              </dl>
            ) : (
              <div className="muted">No adapter coverage event recorded.</div>
            )}
          </div>
        </div>
      </section>
      <section className="panel" style={{ marginTop: 16 }}>
        <div className="panel-header">
          <h2>Trace</h2>
        </div>
        <div className="panel-body">
          <pre className="trace">{trace || "No trace recorded."}</pre>
        </div>
      </section>
      <section className="panel" style={{ marginTop: 16 }}>
        <div className="panel-header">
          <h2>Trace Access Audit</h2>
          <span className="muted">{accessLog.length} access events</span>
        </div>
        <table className="table compact-table">
          <thead>
            <tr>
              <th>Actor</th>
              <th>Accessed</th>
            </tr>
          </thead>
          <tbody>
            {accessLog.map((row) => (
              <tr key={row.id}>
                <td>{row.actor_id}</td>
                <td>{formatDate(row.created_at)}</td>
              </tr>
            ))}
            {accessLog.length === 0 ? (
              <tr>
                <td colSpan={2} className="muted">
                  No trace access recorded.
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      </section>
    </>
  );
}

function canCancel(status: string): boolean {
  return ["queued", "claimed", "running"].includes(status);
}

function formatDate(value: string): string {
  return new Date(value).toLocaleString();
}

type GraphUpdateEvent = {
  kind: "graph_update.completed";
  changed_files: number;
  blast_radius_files: number;
  files: string[];
};

type AdapterCoverageEvent = {
  kind: "adapter.coverage";
  matched_files: string[];
  unmatched_files: string[];
};

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
