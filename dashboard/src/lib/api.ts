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
};

export type Run = {
  id: string;
  kind: string;
  status: string;
  token_spend: number;
  model_used: string | null;
  trace: string;
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

const apiUrl = process.env.NEXT_PUBLIC_SENTINEL_API_URL ?? "http://localhost:8000";

async function get<T>(path: string): Promise<T> {
  const response = await fetch(`${apiUrl}${path}`, { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return response.json() as Promise<T>;
}

export function listFindings(): Promise<Finding[]> {
  return get<Finding[]>("/findings");
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

export function listRuns(): Promise<Run[]> {
  return get<Run[]>("/runs");
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
