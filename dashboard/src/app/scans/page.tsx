import Link from "next/link";
import { Search, ShieldAlert, FileSearch, GitPullRequest, Boxes, Layers } from "lucide-react";
import { listRuns, type Run } from "../../lib/api";
import { getSelectedRepo } from "../../lib/repo";
import { StatusPill, relativeTime, fmtDuration } from "../../components/ui";

const KIND_META: Record<string, { label: string; icon: React.ReactNode }> = {
  source: { label: "Source scan", icon: <Search size={14} /> },
  scan: { label: "Full scan", icon: <Search size={14} /> },
  pentest: { label: "Pentest", icon: <ShieldAlert size={14} /> },
  plan: { label: "Plan review", icon: <FileSearch size={14} /> },
  ingest: { label: "CI ingest", icon: <GitPullRequest size={14} /> }
};

export default async function ScansPage() {
  const [runs, selectedRepo] = await Promise.all([listRuns().catch((): Run[] => []), getSelectedRepo()]);
  const active = runs.filter((r) => ["queued", "claimed", "running"].includes(r.status)).length;

  return (
    <>
      <div className="toolbar">
        <div>
          <div className="eyebrow">Activity</div>
          <h1>Scans</h1>
          <div className="sub">{runs.length} runs{active ? <> · <span className="accent-text">{active} active</span></> : ""} — source scans, pentests, plan reviews and CI ingests</div>
        </div>
        {selectedRepo ? <div className="toolbar-actions"><span className="chip warn" title="Scan history spans every repo in the account"><Layers size={12} /> all repos</span></div> : null}
      </div>

      {runs.length === 0 ? (
        <div className="panel"><div className="empty" style={{ padding: 54 }}><div className="empty-icon"><Boxes size={22} /></div><h3>No scans yet</h3><p>Every <code>sentinel source</code>, <code>sentinel pentest</code>, and CI run shows up here with its cost, model, and full agent trace.</p></div></div>
      ) : (
        <section className="panel flush">
          <table className="table">
            <thead>
              <tr>
                <th>Scan</th>
                <th>Status</th>
                <th style={{ textAlign: "right" }}>Findings</th>
                <th style={{ textAlign: "right" }}>Tokens</th>
                <th>Model</th>
                <th style={{ textAlign: "right" }}>Duration</th>
                <th style={{ textAlign: "right" }}>When</th>
              </tr>
            </thead>
            <tbody>
              {runs.map((run) => {
                const meta = KIND_META[run.kind] ?? { label: run.kind, icon: <Boxes size={14} /> };
                return (
                  <tr key={run.id}>
                    <td>
                      <Link href={`/scans/${run.id}`} className="row-link" style={{ display: "flex", alignItems: "center", gap: 9 }}>
                        <span className="dim" style={{ display: "inline-flex" }}>{meta.icon}</span>
                        <span>
                          <div className="cell-strong">{meta.label}</div>
                          <div className="mono cell-dim" style={{ fontSize: 11 }}>{run.id.slice(0, 8)}</div>
                        </span>
                      </Link>
                    </td>
                    <td><StatusPill status={run.status} /></td>
                    <td className="num" style={{ textAlign: "right" }}>{run.finding_count.toLocaleString()}</td>
                    <td className="num" style={{ textAlign: "right" }}>{run.token_spend.toLocaleString()}</td>
                    <td className="cell-dim">{run.model_used ?? "—"}</td>
                    <td className="num" style={{ textAlign: "right" }}>{fmtDuration(run.created_at, run.completed_at)}</td>
                    <td className="cell-dim" style={{ textAlign: "right" }}>{relativeTime(run.created_at)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </section>
      )}
    </>
  );
}
