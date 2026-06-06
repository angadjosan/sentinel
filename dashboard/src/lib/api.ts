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
