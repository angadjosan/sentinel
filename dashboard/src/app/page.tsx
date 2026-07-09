import Link from "next/link";
import { AlertTriangle, ArrowUpRight, Bug, ShieldCheck, Terminal, Radar, Zap, CircleDollarSign } from "lucide-react";
import { FindingTrend, TokenChart } from "../components/TrendCharts";
import { FindingList } from "../components/FindingList";
import { bySeverity } from "../components/ui";
import { getSelectedRepo } from "../lib/repo";
import {
  type Finding,
  type Run,
  type FindingTrendPoint,
  confirmationRate,
  falsePositiveRate,
  findingTrends,
  listFindings,
  listRuns,
  scanLatency,
  tokenSpend
} from "../lib/api";

export default async function OverviewPage() {
  const repo = await getSelectedRepo();
  const [findings, runs, trends, spend, latency, falsePositive, confirmation] = await Promise.all([
    listFindings({ repo: repo ?? undefined }).catch((): Finding[] => []),
    listRuns().catch((): Run[] => []),
    findingTrends().catch((): FindingTrendPoint[] => []),
    tokenSpend().catch(() => [] as Array<{ input_tokens: number; output_tokens: number }>),
    scanLatency().catch(() => [] as Array<{ kind: string; p90_seconds: number }>),
    falsePositiveRate().catch(() => ({ total: 0, suppressed: 0, rate: 0 })),
    confirmationRate().catch(() => ({ total: 0, confirmed: 0, rate: 0 }))
  ]);

  const open = findings.filter((f) => f.status === "open" || f.status === "suppression_pending");
  const criticalHigh = open.filter((f) => f.severity === "critical" || f.severity === "high");
  const confirmed = findings.filter((f) => f.confirmed);
  const totalTokens = spend.reduce((sum, row) => sum + row.input_tokens + row.output_tokens, 0);
  const p90 = latency.find((row) => row.kind === "source")?.p90_seconds ?? latency[0]?.p90_seconds ?? 0;
  const weekAgo = Date.now() - 7 * 24 * 3600 * 1000;
  const newThisWeek = findings.filter((f) => new Date(f.created_at).getTime() >= weekAgo).length;
  const triage = [...open].sort(bySeverity).slice(0, 6);

  if (findings.length === 0) {
    return <Onboarding scoped={Boolean(repo)} />;
  }

  return (
    <>
      <div className="toolbar">
        <div>
          <div className="eyebrow">Security posture</div>
          <h1>Overview</h1>
          <div className="sub">{repo ? <>Scoped to <span className="accent-text">{repo}</span></> : "All repositories"}</div>
        </div>
        <div className="toolbar-actions">
          <Link href="/findings" className="chip">Triage findings <ArrowUpRight size={13} /></Link>
        </div>
      </div>

      <section className="grid metrics-3">
        <Metric icon={<Bug size={14} />} label="Open findings" value={open.length} foot={`${newThisWeek} new in the last 7 days`} />
        <Metric icon={<AlertTriangle size={14} />} label="Critical & high (open)" value={criticalHigh.length} tone={criticalHigh.length ? "crit" : undefined}
          foot={`${open.filter((f) => f.severity === "critical").length} critical · ${open.filter((f) => f.severity === "high").length} high`} />
        <Metric icon={<ShieldCheck size={14} />} label="Confirmed exploits" value={confirmed.length} tone="accent"
          foot="Reproduced by the pentest oracle" />
      </section>

      <section className="panel" style={{ marginTop: 14 }}>
        <div className="statbar">
          <Stat label="Confirmation rate" value={`${Math.round(confirmation.rate * 100)}%`} sub={`${confirmation.confirmed}/${confirmation.total} findings`} />
          <Stat label="False-positive rate" value={`${Math.round(falsePositive.rate * 100)}%`} sub={`${falsePositive.suppressed} suppressed`} />
          <Stat label="Token spend" value={totalTokens.toLocaleString()} sub="all recorded runs" icon={<CircleDollarSign size={13} />} />
          <Stat label="Source scan p90" value={`${p90.toFixed(1)}s`} sub="latency" icon={<Zap size={13} />} />
        </div>
      </section>

      <section className="grid two" style={{ marginTop: 14 }}>
        <div className="panel">
          <div className="panel-header"><h2>Finding trend</h2><span className="muted">by severity</span></div>
          <div className="panel-body"><FindingTrend points={trends} /></div>
        </div>
        <div className="panel">
          <div className="panel-header"><h2>Token spend</h2><span className="muted">per run</span></div>
          <div className="panel-body"><TokenChart runs={runs} /></div>
        </div>
      </section>

      <section className="panel" style={{ marginTop: 14 }}>
        <div className="panel-header">
          <h2>Triage queue</h2>
          <Link href="/findings" className="link" style={{ fontSize: 13 }}>View all {open.length} open →</Link>
        </div>
        {triage.length ? <FindingList findings={triage} /> : <div className="empty" style={{ padding: "34px" }}><p>Nothing open — you&apos;re all clear.</p></div>}
      </section>
    </>
  );
}

function Metric({ icon, label, value, foot, tone }: { icon: React.ReactNode; label: string; value: number | string; foot?: string; tone?: "crit" | "accent" }) {
  return (
    <div className={`panel metric ${tone ?? ""}`}>
      <div className="label">{icon} {label}</div>
      <div className="value">{typeof value === "number" ? value.toLocaleString() : value}</div>
      {foot ? <div className="metric-foot">{foot}</div> : null}
    </div>
  );
}

function Stat({ label, value, sub, icon }: { label: string; value: string; sub?: string; icon?: React.ReactNode }) {
  return (
    <div className="stat">
      <div className="stat-label">{icon}{label}</div>
      <div className="stat-value">{value}</div>
      {sub ? <div className="stat-sub">{sub}</div> : null}
    </div>
  );
}

function Onboarding({ scoped }: { scoped: boolean }) {
  return (
    <>
      <div className="toolbar">
        <div>
          <div className="eyebrow">Security posture</div>
          <h1>Overview</h1>
        </div>
      </div>
      <div className="panel">
        <div className="empty" style={{ padding: "60px 24px" }}>
          <div className="empty-icon"><Radar size={24} /></div>
          <h3>{scoped ? "No findings for this repository yet" : "Run your first scan"}</h3>
          <p>Sentinel analyzes your diff locally — your source never leaves your machine. Only the code graph and findings sync here.</p>
          <pre className="code-block" style={{ marginTop: 18, minWidth: 420 }}>
{`npm install -g sentineldev
`}<span className="tok-cmd">sentinel</span>{` auth login
`}<span className="tok-cmd">sentinel</span>{` init          `}<span className="tok-comment"># register repo + build the graph</span>{`
`}<span className="tok-cmd">sentinel</span>{` scan          `}<span className="tok-comment"># scan the diff, then pentest each finding</span>
          </pre>
          <div className="wrap" style={{ marginTop: 18 }}>
            <Link className="chip accent" href="/settings#cli"><Terminal size={13} /> Install & connect</Link>
            <Link className="chip" href="/settings#model">Configure model</Link>
          </div>
        </div>
      </div>
    </>
  );
}
