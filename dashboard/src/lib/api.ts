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

const apiUrl = process.env.NEXT_PUBLIC_SENTINEL_API_URL ?? "http://localhost:8000";

async function get<T>(path: string): Promise<T> {
  const response = await fetch(`${apiUrl}${path}`, { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return response.json() as Promise<T>;
}

export function listFindings(filters: { status?: string; severity?: string } = {}): Promise<Finding[]> {
  const params = new URLSearchParams();
  if (filters.status) params.set("status", filters.status);
  if (filters.severity) params.set("severity", filters.severity);
  const suffix = params.toString();
  return get<Finding[]>(`/findings${suffix ? `?${suffix}` : ""}`);
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

export function graphSnapshot(limit = 500): Promise<GraphSnapshot> {
  return get<GraphSnapshot>(`/graph?limit=${limit}`);
}

export function findingGraph(id: string): Promise<GraphSnapshot> {
  return get<GraphSnapshot>(`/findings/${id}/graph`);
}

export function accountConfig(): Promise<AccountConfig> {
  return get<AccountConfig>("/config");
}

export async function updateAccountConfig(patch: AccountConfigPatch): Promise<AccountConfig> {
  const response = await fetch(`${apiUrl}/config`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    cache: "no-store",
    body: JSON.stringify(patch)
  });
  if (!response.ok) throw new Error(await response.text());
  return response.json() as Promise<AccountConfig>;
}

export async function approveDeviceCode(userCode: string): Promise<{ status: string }> {
  const response = await fetch(`${apiUrl}/auth/device/approve`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    cache: "no-store",
    body: JSON.stringify({ user_code: userCode })
  });
  if (!response.ok) throw new Error(await response.text());
  return response.json() as Promise<{ status: string }>;
}

export function listRuns(): Promise<Run[]> {
  return get<Run[]>("/runs");
}

export function getRun(id: string): Promise<Run> {
  return get<Run>(`/runs/${id}`);
}

export async function cancelRun(id: string): Promise<Run> {
  const response = await fetch(`${apiUrl}/runs/${id}`, {
    method: "DELETE",
    cache: "no-store"
  });
  if (!response.ok) throw new Error(await response.text());
  return response.json() as Promise<Run>;
}

export async function runTrace(id: string): Promise<string> {
  const response = await fetch(`${apiUrl}/runs/${id}/trace`, { cache: "no-store" });
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

export async function suppressFinding(id: string, reason: string): Promise<Finding> {
  const response = await fetch(`${apiUrl}/findings/${id}/suppress`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ reason })
  });
  if (!response.ok) throw new Error(await response.text());
  return response.json() as Promise<Finding>;
}

export async function approveSuppression(id: string, reason: string): Promise<Finding> {
  const response = await fetch(`${apiUrl}/findings/${id}/suppress/approve`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ reason })
  });
  if (!response.ok) throw new Error(await response.text());
  return response.json() as Promise<Finding>;
}

export async function rejectSuppression(id: string, reason: string): Promise<Finding> {
  const response = await fetch(`${apiUrl}/findings/${id}/suppress/reject`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ reason })
  });
  if (!response.ok) throw new Error(await response.text());
  return response.json() as Promise<Finding>;
}
