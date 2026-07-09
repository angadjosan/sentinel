import Link from "next/link";
import { accountConfig, currentUser, listFindings, listRepos, listSessions } from "../../lib/api";
import { SeverityBadge } from "../../components/SeverityBadge";
import { RepoPentestConfigForm } from "../../components/RepoPentestConfigForm";
import { SuppressionReviewButtons } from "../../components/SuppressionReviewButtons";
import {
  approveDeviceCodeAction,
  mfaDisableAction,
  resendVerificationAction,
  revokeSessionAction,
  updateAccountConfigAction
} from "./actions";

export default async function TeamPage() {
  const [config, findings, sessions, user, repos] = await Promise.all([
    accountConfig(),
    listFindings(),
    listSessions().catch(() => []),
    currentUser().catch(() => null),
    listRepos().catch(() => [])
  ]);
  const pending = findings.filter((finding) => finding.status === "suppression_pending");

  return (
    <>
      <div className="toolbar">
        <div>
          <h1>Team</h1>
          <div className="muted">Account {config.account_id}</div>
        </div>
      </div>

      <section className="panel" style={{ marginTop: 16 }}>
        <div className="panel-header">
          <h2>How Sentinel runs</h2>
        </div>
        <div className="panel-body">
          <p>
            <strong>SAST runs locally.</strong> Source code and diffs never leave the machine running
            the CLI. Scans call your LLM with a key stored in that machine&apos;s keychain; only the
            code graph (file/line pointers and short labels — never source) and finding metadata sync
            to the cloud.
          </p>
          <p>
            <strong>Pentest runs in the cloud.</strong> The worker confirms a finding by sending HTTP
            payloads to a running instance of your app and checking for a runtime oracle (HTTP or
            sanitizer proof — not the agent&apos;s own say-so). Configure where the worker reaches
            your app per repo below. Its LLM credential is server-side
            (<code>SENTINEL_PENTEST_LLM_API_KEY</code> on the worker), separate from your local SAST key.
          </p>
        </div>
      </section>

      {user ? (
        <section className="panel" style={{ marginTop: 16 }}>
          <div className="panel-header">
            <h2>Security</h2>
          </div>
          <div className="panel-body">
            <div className="kv" style={{ marginBottom: 16 }}>
              <dt>Email</dt>
              <dd>
                {user.email} {user.email_verified ? <span className="badge low">verified</span> : <span className="badge medium">unverified</span>}
                {!user.email_verified ? (
                  <form action={resendVerificationAction} style={{ display: "inline", marginLeft: 8 }}>
                    <button type="submit" style={{ padding: "2px 8px", fontSize: 12 }}>
                      Resend verification email
                    </button>
                  </form>
                ) : null}
              </dd>
              <dt>Two-factor auth</dt>
              <dd>
                {user.mfa_enabled ? (
                  <>
                    <span className="badge low">enabled</span>
                    <form action={mfaDisableAction} className="settings-form compact-form" style={{ marginTop: 8, maxWidth: 320 }}>
                      <label>
                        <span>Current password (required to disable)</span>
                        <input name="password" type="password" required autoComplete="current-password" />
                      </label>
                      <div className="form-actions">
                        <button type="submit" className="danger" style={{ padding: "4px 12px", fontSize: 12 }}>
                          Disable
                        </button>
                      </div>
                    </form>
                  </>
                ) : (
                  <>
                    <span className="badge medium">disabled</span>{" "}
                    <Link href="/team/mfa/setup">Enable two-factor authentication</Link>
                  </>
                )}
              </dd>
            </div>
          </div>
        </section>
      ) : null}

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
          <div className="label">Repos</div>
          <div className="value">{repos.length}</div>
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
              <p className="muted">
                LLM API keys are configured and used locally now — run{" "}
                <code>sentinel config set api-key &lt;key&gt;</code> on each machine that runs scans. The
                server never stores one.
              </p>
              <label>
                <span>API Endpoint</span>
                <input name="api_endpoint" defaultValue={config.api_endpoint ?? ""} placeholder="default provider endpoint" />
              </label>
              <label>
                <span>Monthly Token Budget</span>
                <input name="monthly_token_budget" type="number" min="0" step="1" defaultValue={config.monthly_token_budget ?? ""} placeholder="unlimited" />
              </label>
              {/*
                Source retention is a legacy account field. The cloud never
                receives source code or diffs, so there is nothing to retain —
                the control is hidden but the value is round-tripped so the
                PATCH stays valid while the field exists server-side.
              */}
              <input type="hidden" name="source_retention_days" value={config.source_retention_days} />
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
          <h2>Pentest Configuration</h2>
          <span className="muted">{repos.length} repo{repos.length === 1 ? "" : "s"}</span>
        </div>
        <div className="panel-body">
          <p className="muted">
            Where the cloud worker reaches each repo&apos;s app to run a pentest. Set a reachable{" "}
            staging URL for the hosted worker, or configure a self-hosted worker to boot the app
            itself. No source code is uploaded either way.
          </p>
          {repos.length ? (
            <div className="grid" style={{ gap: 16, marginTop: 8 }}>
              {repos.map((repo) => (
                <div className="panel" key={repo.id}>
                  <div className="panel-header">
                    <h2 style={{ fontSize: 15 }}>{repo.name}</h2>
                    <span className="badge low">{repo.pentest_mode ?? "not configured"}</span>
                  </div>
                  <div className="panel-body">
                    <RepoPentestConfigForm repo={repo} />
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="muted">
              No repos registered yet. Run <code>sentinel init</code> in a repo to register it.
            </div>
          )}
        </div>
      </section>

      <section className="panel" style={{ marginTop: 16 }}>
        <div className="panel-header">
          <h2>Your sessions &amp; devices</h2>
        </div>
        <div className="panel-body">
          {sessions.length ? (
            <table className="table compact-table">
              <thead>
                <tr>
                  <th>Device</th>
                  <th>IP</th>
                  <th>Created</th>
                  <th>Expires</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {sessions.map((session) => (
                  <tr key={session.id}>
                    <td style={{ maxWidth: 320, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={session.user_agent ?? undefined}>
                      {session.label}
                      {session.current ? " (this session)" : ""}
                      {session.user_agent ? ` — ${session.user_agent}` : ""}
                    </td>
                    <td>{session.ip_address ?? "—"}</td>
                    <td>{new Date(session.created_at).toLocaleString()}</td>
                    <td>{new Date(session.expires_at).toLocaleDateString()}</td>
                    <td>
                      <form action={revokeSessionAction}>
                        <input type="hidden" name="id" value={session.id} />
                        <button type="submit" className="danger" style={{ padding: "4px 12px", fontSize: 12 }}>
                          Revoke
                        </button>
                      </form>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="muted">No active sessions.</div>
          )}
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
                      <SuppressionReviewButtons findingId={finding.id} />
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
