import { FindingTable } from "../../components/FindingTable";
import { listFindings } from "../../lib/api";

export default async function FindingsPage() {
  const findings = await listFindings();
  return (
    <>
      <div className="toolbar">
        <h1>Findings</h1>
        <div className="muted">{findings.length} total</div>
      </div>
      <section className="panel">
        <FindingTable findings={findings} />
      </section>
    </>
  );
}
