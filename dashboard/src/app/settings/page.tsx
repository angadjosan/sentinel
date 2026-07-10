import Link from "next/link";
import { BadgeCheck, GitBranch, KeyRound, ShieldCheck, Cpu, CircleDollarSign, Users, Terminal, SlidersHorizontal } from "lucide-react";
import { accountConfig, currentUser, getRepoPentestConfig, listFindings, listMembers, listRepos, listSessions, type AuthUser, type Repo } from "../../lib/api";
import { SeverityBadge, relativeTime } from "../../components/ui";
import { SubmitButton } from "../../components/SubmitButton";
import { SettingsNav } from "../../components/nav/SettingsNav";
import { RepoPentestConfigForm } from "../../components/RepoPentestConfigForm";
import {
  approveDeviceCodeAction,
  approveSuppressionAction,
  createRepoAction,
  mfaDisableAction,
  rejectSuppressionAction,
  resendVerificationAction,
  revokeSessionAction,
  updateAccountConfigAction
} from "./actions";

const SECTIONS = [
  { id: "general", label: "General" },
  { id: "model", label: "Model & providers" },
  { id: "budget", label: "Budget & usage" },
  { id: "repos", label: "Repositories" },
  { id: "members", label: "Members & roles" },
  { id: "security", label: "Security" },
  { id: "policy", label: "Suppression policy" },
  { id: "cli", label: "API & CLI" }
];

export default async function SettingsPage() {
  const [config, findings, sessions, user, repos, members] = await Promise.all([
    accountConfig(),
    listFindings().catch(() => []),
    listSessions().catch(() => []),
    currentUser().catch(() => null),
    listRepos().catch((): Repo[] => []),
    listMembers().catch((): AuthUser[] => [])
  ]);
  const pending = findings.filter((f) => f.status === "suppression_pending");

  // GET /repos omits pentest fields; pull each repo's config so the form pre-fills.
  const pentestConfigs = await Promise.all(repos.map((r) => getRepoPentestConfig(r.id).catch(() => null)));
  const reposWithConfig: Repo[] = repos.map((repo, index) => {
    const config = pentestConfigs[index];
    return config
      ? { ...repo, pentest_mode: config.pentest_mode, staging_base_url: config.staging_base_url, healthcheck_path: config.healthcheck_path, boot: config.boot, healthcheck: config.healthcheck, egress_allowlist: config.egress_allowlist }
      : repo;
  });

  return (
    <>
      <div className="toolbar">
        <div>
          <div className="eyebrow">Account</div>
          <h1>Settings</h1>
          <div className="sub mono" style={{ fontSize: 12 }}>{config.account_id}</div>
        </div>
      </div>

      <div className="settings-shell">
        <SettingsNav sections={SECTIONS} />

        <div>
          <section id="general" className="settings-section">
            <SectionHead icon={<SlidersHorizontal size={15} />} title="General" sub="Account identity and how long source snapshots are retained." />
            <div className="panel"><div className="panel-body">
              <form className="settings-form" action={updateAccountConfigAction}>
                <div className="form-grid">
                  <label><span>Account ID</span><div className="static-field mono">{config.account_id}</div></label>
                  <label><span>Source retention (days)</span><input name="source_retention_days" type="number" min={1} defaultValue={config.source_retention_days} /></label>
                </div>
                <p className="hint">Source snapshots are deleted after this window. Everything analyzed stays on the developer&apos;s machine; only the graph and findings sync here.</p>
                <div className="form-actions"><SubmitButton successMessage="Settings saved">Save</SubmitButton></div>
              </form>
            </div></div>
          </section>

          <section id="model" className="settings-section">
            <SectionHead icon={<Cpu size={15} />} title="Model & providers" sub="Choose the provider and model the local engine uses for analysis." />
            <div className="panel"><div className="panel-body">
              <form className="settings-form" action={updateAccountConfigAction}>
                <div className="form-grid">
                  <label><span>Provider</span>
                    <select name="provider" defaultValue={config.provider}>
                      <option value="local">Local (Ollama)</option>
                      <option value="anthropic">Anthropic</option>
                      <option value="openai">OpenAI</option>
                      <option value="google">Google</option>
                    </select>
                  </label>
                  <label><span>Model</span>
                    <select name="model" defaultValue={config.model}>
                      {modelOptions(config.provider, config.model).map((model) => (<option key={model} value={model}>{model}</option>))}
                    </select>
                  </label>
                </div>
                <label><span>API endpoint (optional)</span><input name="api_endpoint" defaultValue={config.api_endpoint ?? ""} placeholder="default provider endpoint" /></label>
                <div className="wrap" style={{ background: "var(--accent-dim-2)", border: "1px solid var(--border-accent)", borderRadius: "var(--radius-sm)", padding: "10px 12px", alignItems: "center" }}>
                  <KeyRound size={15} className="accent-text" />
                  <span className="hint" style={{ margin: 0 }}>API keys live in your system keychain — run <code>sentinel config set api-key &lt;key&gt;</code> on each machine that scans. The server never stores one.</span>
                </div>
                <div className="form-actions"><SubmitButton successMessage="Settings saved">Save</SubmitButton></div>
              </form>
            </div></div>
          </section>

          <section id="budget" className="settings-section">
            <SectionHead icon={<CircleDollarSign size={15} />} title="Budget & usage" sub="Cap monthly token spend. Scans are rejected once the budget is exceeded." />
            <div className="panel"><div className="panel-body">
              <form className="settings-form" action={updateAccountConfigAction}>
                <label style={{ maxWidth: 320 }}><span>Monthly token budget</span><input name="monthly_token_budget" type="number" min={0} defaultValue={config.monthly_token_budget ?? ""} placeholder="unlimited" /></label>
                <p className="hint">Leave blank for unlimited. Token spend per run is shown in <Link href="/scans" className="link">Scans</Link>.</p>
                <div className="form-actions"><SubmitButton successMessage="Settings saved">Save</SubmitButton></div>
              </form>
            </div></div>
          </section>

          <section id="repos" className="settings-section">
            <SectionHead icon={<GitBranch size={15} />} title="Repositories" sub="Each repo has its own cloud graph. Cross-repo SCA reachability resolves within an account." />
            <div className="panel">
              {repos.length ? (
                <table className="table compact-table">
                  <thead><tr><th>Repository</th><th>Remote</th><th style={{ textAlign: "right" }}>Registered</th></tr></thead>
                  <tbody>
                    {repos.map((repo) => (
                      <tr key={repo.id}><td className="cell-strong"><GitBranch size={13} className="dim" style={{ marginRight: 7, verticalAlign: "-2px" }} />{repo.name}</td><td className="file-ref">{repo.remote_url ?? "—"}</td><td className="cell-dim" style={{ textAlign: "right" }}>{relativeTime(repo.created_at)}</td></tr>
                    ))}
                  </tbody>
                </table>
              ) : <div className="empty" style={{ padding: 26 }}><p>No repositories yet. Run <code>sentinel init</code> in a repo, or add one manually below.</p></div>}
              <div className="panel-body" style={{ borderTop: "1px solid var(--border)" }}>
                <form className="settings-form" action={createRepoAction}>
                  <div className="form-grid">
                    <label><span>Name</span><input name="name" placeholder="acme/service-api" required /></label>
                    <label><span>Remote URL (optional)</span><input name="remote_url" placeholder="https://github.com/acme/service-api" /></label>
                  </div>
                  <div className="form-actions"><SubmitButton successMessage="Repository added" pendingLabel="Adding…">Add repository</SubmitButton></div>
                </form>
              </div>
            </div>
            {repos.length ? (
              <div className="panel" style={{ marginTop: 14 }}>
                <div className="panel-header"><h2>Pentest configuration</h2><span className="muted">where the cloud worker reaches each repo</span></div>
                <div className="panel-body stack" style={{ gap: 20 }}>
                  {reposWithConfig.map((repo) => (
                    <div key={repo.id} className="stack" style={{ gap: 10 }}>
                      <div className="spread">
                        <div className="cell-strong"><GitBranch size={13} className="dim" style={{ marginRight: 7, verticalAlign: "-2px" }} />{repo.name}</div>
                        <span className={`chip ${repo.staging_base_url || repo.boot ? "accent" : ""}`}>{repo.staging_base_url || repo.boot ? repo.pentest_mode : "not configured"}</span>
                      </div>
                      <RepoPentestConfigForm repo={repo} />
                    </div>
                  ))}
                </div>
              </div>
            ) : null}
          </section>

          <section id="members" className="settings-section">
            <SectionHead icon={<Users size={15} />} title="Members & roles" sub="Access is role-gated. Teams share one graph within an account." />
            <div className="stack">
              <div className="panel">
                <div className="panel-header"><h2>Team</h2><span className="muted">{members.length} member{members.length === 1 ? "" : "s"}</span></div>
                {members.length ? (
                  <table className="table compact-table">
                    <thead><tr><th>Member</th><th>Email</th><th>Status</th><th style={{ textAlign: "right" }}>Role</th></tr></thead>
                    <tbody>
                      {members.map((m) => (
                        <tr key={m.id}>
                          <td className="cell-strong" style={{ display: "flex", alignItems: "center", gap: 9 }}>
                            <span className="avatar sm">{(m.name ?? m.email).slice(0, 1).toUpperCase()}</span>
                            {m.name ?? m.email.split("@")[0]}{user && m.id === user.id ? <span className="chip" style={{ marginLeft: 2 }}>you</span> : null}
                          </td>
                          <td className="cell-dim">{m.email}</td>
                          <td>{m.email_verified ? <span className="chip accent"><BadgeCheck size={12} /> verified</span> : <span className="chip warn">unverified</span>}</td>
                          <td style={{ textAlign: "right" }}><span className={`chip ${m.role === "admin" ? "accent" : ""}`} style={{ textTransform: "capitalize" }}>{m.role}</span></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : <div className="empty" style={{ padding: 24 }}><p>Just you so far. Invite teammates from the CLI: <code>sentinel team invite &lt;email&gt; --role member</code>.</p></div>}
              </div>
              <div className="panel"><div className="panel-body">
                <dl className="kv">
                  <dt><span className="chip accent">admin</span></dt><dd>Full access — findings, traces, suppression approval, team &amp; account settings.</dd>
                  <dt><span className="chip">member</span></dt><dd>Read/write findings, run scans, create suppressions (held for approval if enabled).</dd>
                  <dt><span className="chip">readonly</span></dt><dd>Findings and dashboard only — no scan or suppression writes.</dd>
                </dl>
              </div></div>
            </div>
          </section>

          <section id="security" className="settings-section">
            <SectionHead icon={<ShieldCheck size={15} />} title="Security" sub="Your account security and active sessions." />
            <div className="stack">
              {user ? (
                <div className="panel"><div className="panel-body">
                  <dl className="kv">
                    <dt>Email</dt>
                    <dd>{user.email} {user.email_verified ? <span className="chip accent"><BadgeCheck size={12} /> verified</span> : (
                      <form action={resendVerificationAction} style={{ display: "inline" }}><span className="chip warn">unverified</span> <button className="sm" type="submit">Resend</button></form>
                    )}</dd>
                    <dt>Two-factor</dt>
                    <dd>{user.mfa_enabled ? (
                      <>
                        <span className="chip accent">enabled</span>
                        <form action={mfaDisableAction} className="settings-form" style={{ marginTop: 10, maxWidth: 320 }}>
                          <label><span>Current password (to disable)</span><input name="password" type="password" required autoComplete="current-password" /></label>
                          <div className="form-actions"><button className="danger sm" type="submit">Disable 2FA</button></div>
                        </form>
                      </>
                    ) : <><span className="chip warn">disabled</span> <Link className="link" href="/settings/mfa/setup">Enable two-factor →</Link></>}</dd>
                  </dl>
                </div></div>
              ) : null}
              <div className="panel">
                <div className="panel-header"><h2>Sessions &amp; devices</h2><span className="muted">{sessions.length}</span></div>
                {sessions.length ? (
                  <table className="table compact-table">
                    <thead><tr><th>Device</th><th>IP</th><th>Expires</th><th></th></tr></thead>
                    <tbody>
                      {sessions.map((s) => (
                        <tr key={s.id}>
                          <td style={{ maxWidth: 340, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={s.user_agent ?? undefined}>{s.label}{s.current ? <span className="chip accent" style={{ marginLeft: 6 }}>this session</span> : ""}</td>
                          <td className="cell-dim">{s.ip_address ?? "—"}</td>
                          <td className="cell-dim">{new Date(s.expires_at).toLocaleDateString()}</td>
                          <td style={{ textAlign: "right" }}><form action={revokeSessionAction}><input type="hidden" name="id" value={s.id} /><button className="danger sm" type="submit">Revoke</button></form></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : <div className="empty" style={{ padding: 24 }}><p>No active sessions.</p></div>}
              </div>
            </div>
          </section>

          <section id="policy" className="settings-section">
            <SectionHead icon={<BadgeCheck size={15} />} title="Suppression policy" sub="Require admin approval before a member's suppression takes effect." />
            <div className="stack">
              <div className="panel"><div className="panel-body">
                <form className="settings-form" action={updateAccountConfigAction}>
                  <input type="hidden" name="approval_present" value="1" />
                  <label className="checkbox-row"><input name="suppression_approval_required" type="checkbox" defaultChecked={config.suppression_approval_required} /><span>Require admin approval for member suppressions</span></label>
                  <div className="form-actions"><SubmitButton successMessage="Settings saved">Save</SubmitButton></div>
                </form>
              </div></div>
              <div className="panel">
                <div className="panel-header"><h2>Pending approvals</h2><span className="muted">{pending.length}</span></div>
                {pending.length ? (
                  <table className="table compact-table">
                    <thead><tr><th>Severity</th><th>Finding</th><th></th></tr></thead>
                    <tbody>
                      {pending.map((f) => (
                        <tr key={f.id}>
                          <td><SeverityBadge severity={f.severity} /></td>
                          <td><Link className="row-link" href={`/findings/${f.id}`}>{f.title}</Link><div className="muted" style={{ fontSize: 12 }}>{f.vuln_type.replace(/_/g, " ")}</div></td>
                          <td style={{ textAlign: "right" }}>
                            <div className="actions" style={{ justifyContent: "flex-end" }}>
                              <form action={approveSuppressionAction}><input type="hidden" name="finding_id" value={f.id} /><input type="hidden" name="reason" value="Suppression approved by admin in the dashboard" /><button className="primary sm" type="submit">Approve</button></form>
                              <form action={rejectSuppressionAction}><input type="hidden" name="finding_id" value={f.id} /><input type="hidden" name="reason" value="Suppression rejected by admin in the dashboard" /><button className="danger sm" type="submit">Reject</button></form>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : <div className="empty" style={{ padding: 24 }}><p>No suppression requests waiting for review.</p></div>}
              </div>
            </div>
          </section>

          <section id="cli" className="settings-section">
            <SectionHead icon={<Terminal size={15} />} title="API & CLI" sub="Approve a CLI device login and install the tools." />
            <div className="grid two-even">
              <div className="panel"><div className="panel-header"><h2>Approve device login</h2></div><div className="panel-body">
                <form className="settings-form" action={approveDeviceCodeAction}>
                  <label><span>User code from <code>sentinel auth login</code></span><input name="user_code" autoComplete="one-time-code" placeholder="ABCD-EFGH" /></label>
                  <div className="form-actions"><SubmitButton successMessage="Device approved" pendingLabel="Approving…">Approve device</SubmitButton></div>
                </form>
              </div></div>
              <div className="panel"><div className="panel-header"><h2>Install</h2></div><div className="panel-body">
                <pre className="code-block">{`npm install -g sentineldev
pip install sentinel-worker
`}<span className="tok-cmd">sentinel</span>{` auth login`}</pre>
                <p className="hint" style={{ marginTop: 10 }}>Review a plan before code is written in <Link href="/plan" className="link">Plan review</Link>.</p>
              </div></div>
            </div>
          </section>
        </div>
      </div>
    </>
  );
}

function SectionHead({ icon, title, sub }: { icon: React.ReactNode; title: string; sub: string }) {
  return (
    <div style={{ marginBottom: 12 }}>
      <h2 style={{ fontSize: 16, margin: 0, display: "flex", alignItems: "center", gap: 8 }}><span className="accent-text" style={{ display: "inline-flex" }}>{icon}</span>{title}</h2>
      <div className="muted" style={{ fontSize: 13, marginTop: 3 }}>{sub}</div>
    </div>
  );
}

function modelOptions(provider: string, current: string): string[] {
  const options: Record<string, string[]> = {
    anthropic: ["claude-opus-4-8", "claude-sonnet-4-5", "claude-haiku-4-5"],
    openai: ["gpt-5", "gpt-5-mini", "gpt-5-nano"],
    google: ["gemini-2.5-pro", "gemini-2.5-flash"],
    local: ["ollama", "qwen3-coder", "llama-3.3"]
  };
  const all = Object.values(options).flat();
  return Array.from(new Set([...(options[provider] ?? options.local), current, ...all]));
}
