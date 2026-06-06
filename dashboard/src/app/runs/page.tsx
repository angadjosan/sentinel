import Link from "next/link";
import { listRuns } from "../../lib/api";

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
              <th>Tokens</th>
              <th>Model</th>
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
                <td>{run.token_spend.toLocaleString()}</td>
                <td>{run.model_used ?? "not recorded"}</td>
              </tr>
            ))}
            {runs.length === 0 ? (
              <tr>
                <td colSpan={5} className="muted">
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
