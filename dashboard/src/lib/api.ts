export type Finding = {
  id: string;
  vuln_type: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  remediation: string;
  status: string;
  confirmed: boolean;
  evidence: string | null;
  fingerprint: string;
  file: string | null;
  line_start: number | null;
  line_end: number | null;
  created_at: string;
  updated_at: string;
};

export type Run = {
  id: string;
  kind: string;
  status: string;
  finding_count: number;
  token_spend: number;
  model_used: string | null;
  trace: string;
  created_at: string;
  completed_at: string | null;
};

export type TraceAccessLog = {
  id: number;
  run_id: string;
  actor_id: string;
  created_at: string;
};

export type FindingTrendPoint = {
  date: string;
  severity: Finding["severity"];
  count: number;
};

export type EnqueueResult = { task_id: string; run: Run };

export type PullFinding = {
  finding: Finding;
  node: {
    id: string;
    kind: string;
    name: string;
    file: string | null;
    line_start: number | null;
    line_end: number | null;
    language: string | null;
    auth_required: boolean;
    is_entry_point: boolean;
    is_sink: boolean;
    label: string | null;
    intent: string | null;
  } | null;
  remediation_plan: string[];
};

export type SuppressionAudit = {
  id: number;
  finding_id: string;
  action: string;
  actor_id: string;
  reason: string;
  created_at: string;
};

export type GraphNode = {
  id: string;
  kind: string;
  name: string;
  file: string | null;
  line_start: number | null;
  line_end: number | null;
  language: string | null;
  auth_required: boolean;
  is_entry_point: boolean;
  is_sink: boolean;
  label: string | null;
  intent: string | null;
  trust_level: string | null;
  is_new: boolean;
};

export type GraphEdge = {
  id: number;
  src: string;
  dst: string;
  kind: string;
  tainted: boolean;
  sanitized: boolean;
  taint_uncertain: boolean;
  call_uncertainty: string | null;
};

export type GraphSnapshot = {
  nodes: GraphNode[];
  edges: GraphEdge[];
};

/** One selectable graph version for a repo (main or an active branch). */
export type GraphMeta = {
  id: string;
  kind: string;
  branch_name: string | null;
  status: string;
  created_at: string;
};

export type AccountConfig = {
  account_id: string;
  provider: string;
  model: string;
  api_endpoint: string | null;
  suppression_approval_required: boolean;
  monthly_token_budget: number | null;
  source_retention_days: number;
};

export type AccountConfigPatch = {
  provider?: string;
  model?: string;
  api_endpoint?: string | null;
  suppression_approval_required?: boolean;
  monthly_token_budget?: number | null;
  source_retention_days?: number;
};

// Repo pentest configuration (§3 D1 — dual mode). The local CLI engine runs the
// pentest against `staging_base_url` (reach a deployment) or boots the app under
// a gVisor sandbox on the developer's own machine
// (target/egress/secrets/canary/attack-safety declared in `pentest_config`).
export type PentestMode = "staging" | "local_worker";

export type Repo = {
  id: string;
  name: string;
  account_id: string;
  remote_url: string | null;
  created_at: string;
  // Pentest config — present once the repo has been configured.
  pentest_mode?: PentestMode;
  staging_base_url?: string | null;
  healthcheck_path?: string | null;
  boot?: string | null;
  healthcheck?: string | null;
  egress_allowlist?: string[];
};

// Field names are locked by §3 D1 — do not invent new ones.
export type RepoPentestConfigPatch = {
  pentest_mode?: PentestMode;
  staging_base_url?: string | null;
  healthcheck_path?: string | null;
  boot?: string | null;
  healthcheck?: string | null;
  egress_allowlist?: string[];
  pentest_config?: Record<string, unknown> | null;
};

import { getSessionToken } from "./session";

const apiUrl = process.env.SENTINEL_API_INTERNAL_URL ?? process.env.NEXT_PUBLIC_SENTINEL_API_URL ?? "http://localhost:8000";

async function authHeaders(): Promise<Record<string, string>> {
  const token = await getSessionToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function get<T>(path: string): Promise<T> {
  const response = await fetch(`${apiUrl}${path}`, { cache: "no-store", headers: await authHeaders() });
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return response.json() as Promise<T>;
}

async function send<T>(path: string, method: string, body?: unknown, opts: { auth?: boolean } = {}): Promise<T> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (opts.auth !== false) Object.assign(headers, await authHeaders());
  const response = await fetch(`${apiUrl}${path}`, {
    method,
    headers,
    cache: "no-store",
    body: body !== undefined ? JSON.stringify(body) : undefined
  });
  if (!response.ok) throw new Error(await errorDetail(response));
  return response.json() as Promise<T>;
}

async function errorDetail(response: Response): Promise<string> {
  const text = await response.text();
  try {
    const parsed = JSON.parse(text) as { detail?: unknown };
    if (typeof parsed.detail === "string") return parsed.detail;
  } catch {
    // not JSON — fall through to raw text
  }
  return text || `${response.status} ${response.statusText}`;
}

export function createRepo(payload: { name: string; remote_url?: string | null }): Promise<Repo> {
  return send<Repo>("/repos", "POST", payload);
}

export function listFindings(filters: { status?: string; severity?: string; repo?: string } = {}): Promise<Finding[]> {
  const params = new URLSearchParams();
  if (filters.status) params.set("status", filters.status);
  if (filters.severity) params.set("severity", filters.severity);
  if (filters.repo) params.set("repo_name", filters.repo);
  const suffix = params.toString();
  return get<Finding[]>(`/findings${suffix ? `?${suffix}` : ""}`);
}

export function findingTrends(): Promise<FindingTrendPoint[]> {
  return get<FindingTrendPoint[]>("/analytics/finding-trends");
}

export function unsuppressFinding(id: string, reason: string): Promise<Finding> {
  return send<Finding>(`/findings/${id}/unsuppress`, "POST", { reason });
}

export function removeSuppression(id: string): Promise<Finding> {
  return send<Finding>(`/findings/${id}/suppress`, "DELETE");
}

export function startPentest(payload: { finding_id?: string; repo_name?: string; description?: string }): Promise<EnqueueResult> {
  return send<EnqueueResult>("/pentest", "POST", payload);
}

export function reviewPlan(repoId: string, payload: { content: string; with_retry?: boolean }): Promise<EnqueueResult> {
  return send<EnqueueResult>(`/repos/${repoId}/plan`, "POST", payload);
}

export function getFinding(id: string): Promise<Finding> {
  return get<Finding>(`/findings/${id}`);
}

export function pullFinding(id: string): Promise<PullFinding> {
  return get<PullFinding>(`/findings/${id}/pull`);
}

export function findingAudit(id: string): Promise<SuppressionAudit[]> {
  return get<SuppressionAudit[]>(`/findings/${id}/audit`);
}

export function graphSnapshot(
  limit = 500,
  opts: { repoName?: string | null; graphKind?: string; branchName?: string | null } = {}
): Promise<GraphSnapshot> {
  const params = new URLSearchParams({ limit: String(limit) });
  if (opts.repoName) params.set("repo_name", opts.repoName);
  if (opts.graphKind && opts.graphKind !== "main") params.set("graph_kind", opts.graphKind);
  if (opts.branchName) params.set("branch_name", opts.branchName);
  return get<GraphSnapshot>(`/graph?${params.toString()}`);
}

export function listGraphs(repoName: string): Promise<GraphMeta[]> {
  return get<GraphMeta[]>(`/graphs?repo_name=${encodeURIComponent(repoName)}`);
}

export function findingGraph(id: string): Promise<GraphSnapshot> {
  return get<GraphSnapshot>(`/findings/${id}/graph`);
}

export function listRepos(): Promise<Repo[]> {
  return get<Repo[]>("/repos");
}

export function getRepo(id: string): Promise<Repo> {
  return get<Repo>(`/repos/${id}`);
}

export type RepoPentestConfig = {
  repo_id: string;
  pentest_mode: PentestMode;
  staging_base_url: string | null;
  healthcheck_path: string | null;
  boot: string | null;
  healthcheck: string | null;
  egress_allowlist: string[];
  pentest_config?: Record<string, unknown> | null;
};

export function getRepoPentestConfig(id: string): Promise<RepoPentestConfig> {
  return get<RepoPentestConfig>(`/repos/${id}/pentest-config`);
}

// PATCH the repo's pentest configuration. Only §3 D1 fields are sent.
export function updateRepoPentestConfig(id: string, patch: RepoPentestConfigPatch): Promise<Repo> {
  return send<Repo>(`/repos/${id}/pentest-config`, "PATCH", patch);
}

export function accountConfig(): Promise<AccountConfig> {
  return get<AccountConfig>("/config");
}

export function updateAccountConfig(patch: AccountConfigPatch): Promise<AccountConfig> {
  return send<AccountConfig>("/config", "PATCH", patch);
}

export function approveDeviceCode(userCode: string): Promise<{ status: string }> {
  return send<{ status: string }>("/auth/device/approve", "POST", { user_code: userCode });
}

export function listRuns(): Promise<Run[]> {
  return get<Run[]>("/runs");
}

export function getRun(id: string): Promise<Run> {
  return get<Run>(`/runs/${id}`);
}

export function cancelRun(id: string): Promise<Run> {
  return send<Run>(`/runs/${id}`, "DELETE");
}

export async function runTrace(id: string): Promise<string> {
  const response = await fetch(`${apiUrl}/runs/${id}/trace`, { cache: "no-store", headers: await authHeaders() });
  if (!response.ok) throw new Error(await response.text());
  return response.text();
}

export function traceAccessLog(id: string): Promise<TraceAccessLog[]> {
  return get<TraceAccessLog[]>(`/runs/${id}/trace-access`);
}

export function tokenSpend(): Promise<Array<{ component: string; input_tokens: number; output_tokens: number; est_cost_usd: number }>> {
  return get("/analytics/token-spend");
}

export function scanLatency(): Promise<Array<{ kind: string; p50_seconds: number; p90_seconds: number; count: number }>> {
  return get("/analytics/scan-latency");
}

export function falsePositiveRate(): Promise<{ total: number; suppressed: number; rate: number }> {
  return get("/analytics/false-positive-rate");
}

export function confirmationRate(): Promise<{ total: number; confirmed: number; rate: number }> {
  return get("/analytics/confirmation-rate");
}

export function suppressFinding(id: string, reason: string): Promise<Finding> {
  return send<Finding>(`/findings/${id}/suppress`, "PATCH", { reason });
}

export function approveSuppression(id: string, reason: string): Promise<Finding> {
  return send<Finding>(`/findings/${id}/suppress/approve`, "POST", { reason });
}

export function rejectSuppression(id: string, reason: string): Promise<Finding> {
  return send<Finding>(`/findings/${id}/suppress/reject`, "POST", { reason });
}

// ── Auth ──────────────────────────────────────────────────────────────────────

export type AuthUser = {
  id: string;
  email: string;
  name: string | null;
  role: "admin" | "member" | "readonly" | string;
  account_id: string;
  account_name: string;
  email_verified: boolean;
  mfa_enabled: boolean;
};

export type AuthResult = { access_token: string; user: AuthUser };

export type LoginResult = {
  mfa_required: boolean;
  challenge_token?: string;
  access_token?: string;
  user?: AuthUser;
};

export type SessionInfo = {
  id: string;
  label: string;
  created_at: string;
  expires_at: string;
  last_seen_at: string;
  user_agent: string | null;
  ip_address: string | null;
  current: boolean;
};

export function signupRequest(payload: { name: string; email: string; password: string; account_name?: string }): Promise<AuthResult> {
  return send<AuthResult>("/auth/signup", "POST", payload, { auth: false });
}

export function loginRequest(payload: { email: string; password: string }): Promise<LoginResult> {
  return send<LoginResult>("/auth/login", "POST", payload, { auth: false });
}

export function loginMfaRequest(payload: { challenge_token: string; code: string }): Promise<AuthResult> {
  return send<AuthResult>("/auth/login/mfa", "POST", payload, { auth: false });
}

export function logoutRequest(): Promise<{ status: string }> {
  return send<{ status: string }>("/auth/logout", "POST");
}

export function currentUser(): Promise<AuthUser> {
  return get<AuthUser>("/auth/me");
}

export function listMembers(): Promise<AuthUser[]> {
  return get<AuthUser[]>("/auth/members");
}

export function listSessions(): Promise<SessionInfo[]> {
  return get<SessionInfo[]>("/auth/sessions");
}

export function revokeSession(id: string): Promise<{ status: string }> {
  return send<{ status: string }>(`/auth/sessions/${id}`, "DELETE");
}

export function forgotPasswordRequest(email: string): Promise<{ status: string }> {
  return send<{ status: string }>("/auth/forgot-password", "POST", { email }, { auth: false });
}

export function resetPasswordRequest(payload: { token: string; password: string }): Promise<{ status: string }> {
  return send<{ status: string }>("/auth/reset-password", "POST", payload, { auth: false });
}

export function verifyEmailRequest(token: string): Promise<{ status: string }> {
  return send<{ status: string }>(`/auth/verify-email?token=${encodeURIComponent(token)}`, "POST", undefined, { auth: false });
}

export function resendVerificationEmail(): Promise<{ status: string }> {
  return send<{ status: string }>("/auth/verify-email/resend", "POST");
}

export type MfaEnrollment = { secret: string; otpauth_url: string };

export function mfaEnroll(): Promise<MfaEnrollment> {
  return send<MfaEnrollment>("/auth/mfa/enroll", "POST");
}

export function mfaConfirm(code: string): Promise<{ status: string }> {
  return send<{ status: string }>("/auth/mfa/confirm", "POST", { code });
}

export function mfaDisable(password: string): Promise<{ status: string }> {
  return send<{ status: string }>("/auth/mfa/disable", "POST", { password });
}

export function githubOAuthLogin(payload: { code: string; redirect_uri: string }): Promise<AuthResult> {
  return send<AuthResult>("/auth/oauth/github", "POST", payload, { auth: false });
}
