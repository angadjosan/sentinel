import { FindingTable } from "../../components/FindingTable";
import { listFindings } from "../../lib/api";

export default async function FindingsPage({ searchParams }: { searchParams: Promise<{ status?: string; severity?: string }> }) {
  const filters = await searchParams;
  const findings = await listFindings({ status: filters.status, severity: filters.severity });
  return (
    <>
      <div className="toolbar">
        <h1>Findings</h1>
        <div className="muted">{findings.length} total</div>
      </div>
      <section className="panel filter-panel">
        <form className="filter-form">
          <label>
            <span>Status</span>
            <select name="status" defaultValue={filters.status ?? ""}>
              <option value="">All</option>
              <option value="open">Open</option>
              <option value="confirmed">Confirmed</option>
              <option value="suppressed">Suppressed</option>
              <option value="suppression_pending">Suppression Pending</option>
              <option value="fixed">Fixed</option>
              <option value="not_reproducible">Not Reproducible</option>
            </select>
          </label>
          <label>
            <span>Severity</span>
            <select name="severity" defaultValue={filters.severity ?? ""}>
              <option value="">All</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
          </label>
          <button type="submit" className="primary">Apply</button>
        </form>
      </section>
      <section className="panel">
        <FindingTable findings={findings} />
      </section>
    </>
  );
}
