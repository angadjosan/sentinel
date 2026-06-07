import Link from "next/link";
import { accountConfig, listFindings } from "../../lib/api";
import { SeverityBadge } from "../../components/SeverityBadge";
import { approveDeviceCodeAction, approveSuppressionAction, rejectSuppressionAction, updateAccountConfigAction } from "./actions";

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
            <form className="settings-form" action={updateAccountConfigAction}>
              <label>
                <span>Provider</span>
                <select name="provider" defaultValue={config.provider}>
                  <option value="local">Local</option>
                  <option value="anthropic">Anthropic</option>
                  <option value="openai">OpenAI</option>
                  <option value="google">Google</option>
                </select>
              </label>
              <label>
                <span>Model</span>
                <select name="model" defaultValue={config.model}>
                  {modelOptions(config.provider, config.model).map((model) => (
                    <option key={model} value={model}>
                      {model}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                <span>API Endpoint</span>
                <input name="api_endpoint" defaultValue={config.api_endpoint ?? ""} placeholder="default provider endpoint" />
              </label>
              <label>
                <span>Monthly Token Budget</span>
                <input name="monthly_token_budget" type="number" min="0" step="1" defaultValue={config.monthly_token_budget ?? ""} placeholder="unlimited" />
              </label>
              <label>
                <span>Source Retention Days</span>
                <input name="source_retention_days" type="number" min="1" step="1" defaultValue={config.source_retention_days} />
              </label>
              <label className="checkbox-row">
                <input name="suppression_approval_required" type="checkbox" defaultChecked={config.suppression_approval_required} />
                <span>Require admin approval for member suppressions</span>
              </label>
              <div className="form-actions">
                <button type="submit" className="primary">Save Settings</button>
              </div>
            </form>
          </div>
        </div>

        <div className="panel">
          <div className="panel-header">
            <h2>Device Login</h2>
          </div>
          <div className="panel-body">
            <form className="settings-form compact-form" action={approveDeviceCodeAction}>
              <label>
                <span>User Code</span>
                <input name="user_code" autoComplete="one-time-code" placeholder="ABCD-EFGH" />
              </label>
              <div className="form-actions">
                <button type="submit" className="primary">Approve Device</button>
              </div>
            </form>
          </div>
        </div>
      </section>

      <section className="panel" style={{ marginTop: 16 }}>
        <div className="panel-header">
          <h2>Pending Suppression Approvals ({pending.length})</h2>
        </div>
        <div className="panel-body">
          {pending.length ? (
            <table className="table compact-table">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Finding</th>
                  <th>Type</th>
                  <th>Actions</th>
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
                    <td>
                      <div style={{ display: "flex", gap: 8 }}>
                        <form action={approveSuppressionAction} style={{ display: "inline" }}>
                          <input type="hidden" name="finding_id" value={finding.id} />
                          <input type="hidden" name="reason" value="Approved by admin" />
                          <button type="submit" className="primary" style={{ padding: "4px 12px", fontSize: 12 }}>
                            Approve
                          </button>
                        </form>
                        <form action={rejectSuppressionAction} style={{ display: "inline" }}>
                          <input type="hidden" name="finding_id" value={finding.id} />
                          <input type="hidden" name="reason" value="Rejected by admin" />
                          <button type="submit" className="danger" style={{ padding: "4px 12px", fontSize: 12 }}>
                            Reject
                          </button>
                        </form>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="muted">No suppression requests waiting for review.</div>
          )}
        </div>
      </section>
    </>
  );
}

function modelOptions(provider: string, current: string): string[] {
  const options: Record<string, string[]> = {
    anthropic: ["claude-opus-4-8", "claude-sonnet-4-5", "claude-haiku-4-5"],
    openai: ["gpt-5", "gpt-5-mini", "gpt-5-nano"],
    google: ["gemini-2.5-pro", "gemini-2.5-flash"],
    local: ["ollama", "qwen3-coder", "llama-3.3"]
  };
  const allModels = Object.values(options).flat();
  return Array.from(new Set([...(options[provider] ?? options.local), current, ...allModels]));
}
