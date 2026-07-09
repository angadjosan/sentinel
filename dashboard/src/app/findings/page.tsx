import Link from "next/link";
import { FindingList } from "../../components/FindingList";
import { FindingsSearch } from "../../components/FindingsSearch";
import { bySeverity } from "../../components/ui";
import { getSelectedRepo } from "../../lib/repo";
import { listFindings, type Finding } from "../../lib/api";

type Params = { status?: string; severity?: string; view?: string; q?: string };

const STATUSES = ["open", "confirmed", "suppression_pending", "suppressed", "fixed", "not_reproducible"];
const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const VIEWS: Record<string, { label: string; test: (f: Finding) => boolean }> = {
  review: { label: "Needs review", test: (f) => (f.status === "open" || f.status === "suppression_pending") && (f.severity === "critical" || f.severity === "high") },
  exploited: { label: "Confirmed exploits", test: (f) => f.confirmed },
  pending: { label: "Suppression pending", test: (f) => f.status === "suppression_pending" }
};

export default async function FindingsPage({ searchParams }: { searchParams: Promise<Params> }) {
  const params = await searchParams;
  const repo = await getSelectedRepo();
  const all = await listFindings({ repo: repo ?? undefined }).catch((): Finding[] => []);

  const view = params.view && VIEWS[params.view] ? params.view : undefined;
  let filtered = all;
  if (view) filtered = filtered.filter(VIEWS[view].test);
  if (params.status) filtered = filtered.filter((f) => f.status === params.status);
  if (params.severity) filtered = filtered.filter((f) => f.severity === params.severity);
  const q = (params.q ?? "").trim().toLowerCase();
  if (q) filtered = filtered.filter((f) => [f.title, f.vuln_type, f.file, f.description].some((v) => v?.toLowerCase().includes(q)));
  filtered = [...filtered].sort(bySeverity);

  const count = (test: (f: Finding) => boolean) => all.filter(test).length;
  const href = (patch: Partial<Params>) => {
    const next = { ...params, ...patch };
    const qs = new URLSearchParams();
    if (next.view) qs.set("view", next.view);
    if (next.status) qs.set("status", next.status);
    if (next.severity) qs.set("severity", next.severity);
    const s = qs.toString();
    return `/findings${s ? `?${s}` : ""}`;
  };

  return (
    <>
      <div className="toolbar">
        <div>
          <div className="eyebrow">Triage</div>
          <h1>Findings</h1>
          <div className="sub">{filtered.length} of {all.length}{repo ? <> in <span className="accent-text">{repo}</span></> : ""}</div>
        </div>
        <div className="toolbar-actions">
          <FindingsSearch />
        </div>
      </div>

      <div className="inbox">
        <aside className="filter-rail">
          <div className="filter-group">
            <div className="filter-title">Views</div>
            {Object.entries(VIEWS).map(([key, v]) => (
              <Link key={key} href={href({ view: view === key ? undefined : key, status: undefined, severity: undefined })} className={`filter-link ${view === key ? "active" : ""}`}>
                <span style={{ display: "flex", alignItems: "center", gap: 8 }}><span className="filter-dot" />{v.label}</span>
                <span className="count">{count(v.test)}</span>
              </Link>
            ))}
          </div>

          <div className="filter-group">
            <div className="filter-title">Status</div>
            <Link href={href({ status: undefined })} className={`filter-link ${!params.status ? "active" : ""}`}>
              <span style={{ display: "flex", alignItems: "center", gap: 8 }}><span className="filter-dot" />All</span>
              <span className="count">{all.length}</span>
            </Link>
            {STATUSES.map((status) => (
              <Link key={status} href={href({ status: params.status === status ? undefined : status })} className={`filter-link ${params.status === status ? "active" : ""}`}>
                <span style={{ display: "flex", alignItems: "center", gap: 8, textTransform: "capitalize" }}><span className="filter-dot" />{status.replace(/_/g, " ")}</span>
                <span className="count">{count((f) => f.status === status)}</span>
              </Link>
            ))}
          </div>

          <div className="filter-group">
            <div className="filter-title">Severity</div>
            {SEVERITIES.map((severity) => (
              <Link key={severity} href={href({ severity: params.severity === severity ? undefined : severity })} className={`filter-link ${params.severity === severity ? "active" : ""}`}>
                <span style={{ display: "flex", alignItems: "center", gap: 8 }}><span className={`sev-dot ${severity}`} /><span style={{ textTransform: "capitalize" }}>{severity}</span></span>
                <span className="count">{count((f) => f.severity === severity)}</span>
              </Link>
            ))}
          </div>
        </aside>

        <div>
          <section className="panel flush">
            <FindingList findings={filtered} keyboard />
          </section>
          <div className="muted" style={{ display: "flex", gap: 12, fontSize: 12, marginTop: 10, paddingLeft: 4 }}>
            <span><span className="kbd">j</span> <span className="kbd">k</span> move</span>
            <span><span className="kbd">o</span> open</span>
            <span><span className="kbd">e</span> suppress</span>
          </div>
        </div>
      </div>
    </>
  );
}
