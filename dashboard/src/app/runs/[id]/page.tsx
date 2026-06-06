import { listRuns } from "../../../lib/api";

export default async function RunDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const runs = await listRuns();
  const run = runs.find((candidate) => candidate.id === id);
  if (!run) {
    return (
      <>
        <div className="toolbar">
          <h1>Run Not Found</h1>
        </div>
      </>
    );
  }
  return (
    <>
      <div className="toolbar">
        <h1>Run Trace</h1>
        <div className="muted">{run.id}</div>
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
          <div className="label">Model</div>
          <div className="value">{run.model_used ?? "n/a"}</div>
        </div>
      </section>
      <section className="panel" style={{ marginTop: 16 }}>
        <div className="panel-header">
          <h2>Trace</h2>
        </div>
        <div className="panel-body">
          <pre className="trace">{run.trace || "No trace recorded."}</pre>
        </div>
      </section>
    </>
  );
}
