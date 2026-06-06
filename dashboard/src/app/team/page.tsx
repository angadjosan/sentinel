import Link from "next/link";
import { accountConfig, listFindings } from "../../lib/api";
import { SeverityBadge } from "../../components/SeverityBadge";

export default async function TeamPage() {
  const [config, findings] = await Promise.all([accountConfig(), listFindings()]);
  const pending = findings.filter((finding) => finding.status === "suppression_pending");

  return (
    <>
      <div className="toolbar">
        <div>
          <h1>Team</h1>
          <div className="muted">Account {config.account_id}</div>
        </div>
      </div>

      <section className="grid metrics">
        <div className="panel metric">
          <div className="label">Provider</div>
          <div className="value">{config.provider}</div>
        </div>
        <div className="panel metric">
          <div className="label">Model</div>
          <div className="value">{config.model}</div>
        </div>
        <div className="panel metric">
          <div className="label">Monthly Budget</div>
          <div className="value">{config.monthly_token_budget?.toLocaleString() ?? "none"}</div>
        </div>
        <div className="panel metric">
          <div className="label">Source Retention</div>
          <div className="value">{config.source_retention_days}d</div>
        </div>
      </section>

      <section className="grid two detail-grid">
        <div className="panel">
          <div className="panel-header">
            <h2>Account Settings</h2>
          </div>
          <div className="panel-body">
            <dl className="kv">
              <dt>API Endpoint</dt>
              <dd>{config.api_endpoint ?? "default"}</dd>
              <dt>Suppression Approval</dt>
              <dd>{config.suppression_approval_required ? "required" : "not required"}</dd>
              <dt>Token Budget</dt>
              <dd>{config.monthly_token_budget?.toLocaleString() ?? "unlimited"}</dd>
              <dt>Source Retention</dt>
              <dd>{config.source_retention_days} days</dd>
            </dl>
          </div>
        </div>

        <div className="panel">
          <div className="panel-header">
            <h2>Suppression Queue</h2>
            <span className="muted">{pending.length} pending</span>
          </div>
          <div className="panel-body">
            {pending.length ? (
              <table className="table compact-table">
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Finding</th>
                    <th>Type</th>
                  </tr>
                </thead>
                <tbody>
                  {pending.map((finding) => (
                    <tr key={finding.id}>
                      <td>
                        <SeverityBadge severity={finding.severity} />
                      </td>
                      <td>
                        <Link className="row-link" href={`/findings/${finding.id}`}>
                          {finding.title}
                        </Link>
                      </td>
                      <td>{finding.vuln_type}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <div className="muted">No suppression requests waiting for review.</div>
            )}
          </div>
        </div>
      </section>
    </>
  );
}
