import Link from "next/link";
import { listRuns } from "../../lib/api";
import { cancelRunAction } from "./actions";

export default async function RunsPage() {
  const runs = await listRuns();
  return (
    <>
      <div className="toolbar">
        <h1>Runs</h1>
        <div className="muted">{runs.length} recorded</div>
      </div>
      <section className="panel">
        <table className="table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Kind</th>
              <th>Status</th>
              <th>Findings</th>
              <th>Tokens</th>
              <th>Model</th>
              <th>Created</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {runs.map((run) => (
              <tr key={run.id}>
                <td>
                  <Link href={`/runs/${run.id}`}>{run.id}</Link>
                </td>
                <td>{run.kind}</td>
                <td>{run.status}</td>
                <td>{run.finding_count.toLocaleString()}</td>
                <td>{run.token_spend.toLocaleString()}</td>
                <td>{run.model_used ?? "not recorded"}</td>
                <td>{formatDate(run.created_at)}</td>
                <td>
                  {canCancel(run.status) ? (
                    <form action={cancelRunAction}>
                      <input type="hidden" name="runId" value={run.id} />
                      <button type="submit" className="danger">Cancel</button>
                    </form>
                  ) : (
                    <span className="muted">No action</span>
                  )}
                </td>
              </tr>
            ))}
            {runs.length === 0 ? (
              <tr>
                <td colSpan={8} className="muted">
                  No runs recorded.
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
