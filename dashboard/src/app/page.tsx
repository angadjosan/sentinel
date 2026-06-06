import { FindingTable } from "../components/FindingTable";
import { FindingTrend, TokenChart } from "../components/TrendCharts";
import { listFindings, listRuns, tokenSpend } from "../lib/api";

export default async function OverviewPage() {
  const [findings, runs, spend] = await Promise.all([listFindings(), listRuns(), tokenSpend()]);
  const open = findings.filter((finding) => finding.status === "open").length;
  const confirmed = findings.filter((finding) => finding.confirmed).length;
  const critical = findings.filter((finding) => finding.severity === "critical").length;
  const totalTokens = spend.reduce((sum, row) => sum + row.input_tokens + row.output_tokens, 0);

  return (
    <>
      <div className="toolbar">
        <h1>Security Overview</h1>
      </div>
      <section className="grid metrics">
        <div className="panel metric">
          <div className="label">Open Findings</div>
          <div className="value">{open}</div>
        </div>
        <div className="panel metric">
          <div className="label">Confirmed</div>
          <div className="value">{confirmed}</div>
        </div>
        <div className="panel metric">
          <div className="label">Critical</div>
          <div className="value">{critical}</div>
        </div>
        <div className="panel metric">
          <div className="label">Tokens</div>
          <div className="value">{totalTokens.toLocaleString()}</div>
        </div>
      </section>
      <section className="grid two" style={{ marginTop: 16 }}>
        <div className="panel">
          <div className="panel-header">
            <h2>Finding Trend</h2>
          </div>
          <div className="panel-body">
            <FindingTrend findings={findings} />
          </div>
        </div>
        <div className="panel">
          <div className="panel-header">
            <h2>Token Spend</h2>
          </div>
          <div className="panel-body">
            <TokenChart runs={runs} />
          </div>
        </div>
      </section>
      <section className="panel" style={{ marginTop: 16 }}>
        <div className="panel-header">
          <h2>Latest Findings</h2>
        </div>
        <FindingTable findings={findings.slice(0, 8)} />
      </section>
    </>
  );
}
