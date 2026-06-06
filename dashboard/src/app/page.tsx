import { FindingTable } from "../components/FindingTable";
import { FindingTrend, TokenChart } from "../components/TrendCharts";
import { confirmationRate, falsePositiveRate, listFindings, listRuns, scanLatency, tokenSpend } from "../lib/api";

export default async function OverviewPage() {
  const [findings, runs, spend, latency, falsePositive, confirmation] = await Promise.all([
    listFindings(),
    listRuns(),
    tokenSpend(),
    scanLatency(),
    falsePositiveRate(),
    confirmationRate()
  ]);
  const open = findings.filter((finding) => finding.status === "open").length;
  const critical = findings.filter((finding) => finding.severity === "critical").length;
  const totalTokens = spend.reduce((sum, row) => sum + row.input_tokens + row.output_tokens, 0);
  const p90 = latency.find((row) => row.kind === "source")?.p90_seconds ?? 0;

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
          <div className="value">{confirmation.confirmed}</div>
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
      <section className="grid metrics" style={{ marginTop: 16 }}>
        <div className="panel metric">
          <div className="label">False Positive Rate</div>
          <div className="value">{Math.round(falsePositive.rate * 100)}%</div>
        </div>
        <div className="panel metric">
          <div className="label">Confirmation Rate</div>
          <div className="value">{Math.round(confirmation.rate * 100)}%</div>
        </div>
        <div className="panel metric">
          <div className="label">Source p90</div>
          <div className="value">{p90.toFixed(2)}s</div>
        </div>
        <div className="panel metric">
          <div className="label">Suppressed</div>
          <div className="value">{falsePositive.suppressed}</div>
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
