import { loadConfig, SentinelConfig } from "../config/sentinel.config.js";

export type Finding = {
  id: string;
  vuln_type: string;
  severity: string;
  title: string;
  description: string;
  remediation: string;
  status: string;
  confirmed: boolean;
  evidence?: string | null;
  fingerprint: string;
};

export type Run = {
  id: string;
  kind: string;
  status: string;
  token_spend: number;
  model_used?: string | null;
  trace: string;
};

export class SentinelApiClient {
  constructor(private readonly config: SentinelConfig = loadConfig()) {}

  async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const response = await fetch(`${this.config.apiUrl}${path}`, {
      ...init,
      headers: {
        "Content-Type": "application/json",
        ...(init.headers ?? {})
      }
    });
    if (!response.ok) {
      const detail = await response.text();
      throw new Error(`${response.status} ${response.statusText}: ${detail}`);
    }
    return response.json() as Promise<T>;
  }

  init(files: Record<string, string>) {
    return this.request<Run>("/init", {
      method: "POST",
      body: JSON.stringify({ repo_name: this.config.repoName, files })
    });
  }

  source(diff: string, runContext: string) {
    return this.request<{ run: Run; findings: Finding[] }>("/source", {
      method: "POST",
      body: JSON.stringify({ repo_name: this.config.repoName, diff, run_context: runContext })
    });
  }

  findings() {
    return this.request<Finding[]>("/findings");
  }

  suppress(id: string, reason: string) {
    return this.request<Finding>(`/findings/${id}/suppress`, {
      method: "PATCH",
      body: JSON.stringify({ reason })
    });
  }

  unsuppress(id: string, reason: string) {
    return this.request<Finding>(`/findings/${id}/unsuppress`, {
      method: "POST",
      body: JSON.stringify({ reason })
    });
  }

  pentest(id: string, sanitizerOutput = "", behavioralProof?: string, proofDetail = "") {
    return this.request<Finding>("/pentest", {
      method: "POST",
      body: JSON.stringify({
        repo_name: this.config.repoName,
        finding_id: id,
        sanitizer_output: sanitizerOutput,
        behavioral_proof: behavioralProof,
        proof_detail: proofDetail
      })
    });
  }

  runs() {
    return this.request<Run[]>("/runs");
  }

  run(id: string) {
    return this.request<Run>(`/runs/${id}`);
  }

  trace(id: string) {
    return fetch(`${this.config.apiUrl}/runs/${id}/trace`).then((response) => response.text());
  }
}
