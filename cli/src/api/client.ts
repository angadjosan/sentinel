import { loadConfig, SentinelConfig } from "../config/sentinel.config.js";
import { readApiKey } from "../auth/keychain.js";

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

export type DeviceAuthStart = {
  device_code: string;
  user_code: string;
  verification_url: string;
  expires_in: number;
};

export type DeviceAuthToken =
  | { status: "pending" }
  | {
      status: "approved";
      access_token: string;
      account_id: string;
      user_id: string;
    };

export class SentinelApiClient {
  constructor(private readonly config: SentinelConfig = loadConfig()) {}

  private async authHeaders(): Promise<Record<string, string>> {
    const token = await readApiKey(this.config);
    return token ? { Authorization: `Bearer ${token}` } : {};
  }

  async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const response = await fetch(`${this.config.apiUrl}${path}`, {
      ...init,
      headers: {
        "Content-Type": "application/json",
        ...(await this.authHeaders()),
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

  startDeviceAuth() {
    return this.request<DeviceAuthStart>("/auth/device", { method: "POST" });
  }

  async deviceAuthToken(deviceCode: string): Promise<DeviceAuthToken> {
    const response = await fetch(`${this.config.apiUrl}/auth/device/token?device_code=${encodeURIComponent(deviceCode)}`, {
      headers: await this.authHeaders()
    });
    if (response.status === 202) {
      return { status: "pending" };
    }
    if (!response.ok) {
      throw new Error(`${response.status} ${response.statusText}: ${await response.text()}`);
    }
    const body = (await response.json()) as Omit<Extract<DeviceAuthToken, { status: "approved" }>, "status">;
    return { status: "approved", ...body };
  }

  source(diff: string, runContext: string, scope: { baseRef?: string; paths?: string[] } = {}) {
    return this.request<{ run: Run; findings: Finding[] }>("/source", {
      method: "POST",
      body: JSON.stringify({ repo_name: this.config.repoName, diff, run_context: runContext, base_ref: scope.baseRef, paths: scope.paths ?? [] })
    });
  }

  enqueueSource(diff: string, runContext: string, scope: { baseRef?: string; paths?: string[] } = {}) {
    return this.request<{ task_id: string; run: Run }>("/source/enqueue", {
      method: "POST",
      body: JSON.stringify({ repo_name: this.config.repoName, diff, run_context: runContext, base_ref: scope.baseRef, paths: scope.paths ?? [] })
    });
  }

  findings() {
    return this.request<Finding[]>(`/findings?repo_name=${encodeURIComponent(this.config.repoName)}`);
  }

  finding(id: string) {
    return this.request<Finding>(`/findings/${id}`);
  }

  pull(id: string) {
    return this.request<{ finding: Finding; node: unknown; remediation_plan: string[] }>(`/findings/${id}/pull`);
  }

  plan(content: string, withRetry: boolean) {
    return this.request<{ run: Run; findings: Finding[] }>("/plan", {
      method: "POST",
      body: JSON.stringify({ repo_name: this.config.repoName, content, with_retry: withRetry })
    });
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

  approveSuppression(id: string, reason: string) {
    return this.request<Finding>(`/findings/${id}/suppress/approve`, {
      method: "POST",
      body: JSON.stringify({ reason })
    });
  }

  rejectSuppression(id: string, reason: string) {
    return this.request<Finding>(`/findings/${id}/suppress/reject`, {
      method: "POST",
      body: JSON.stringify({ reason })
    });
  }

  pentest(target: { findingId?: string; description?: string } = {}, sanitizerOutput = "", behavioralProof?: string, proofDetail = "") {
    return this.request<Finding>("/pentest", {
      method: "POST",
      body: JSON.stringify({
        repo_name: this.config.repoName,
        finding_id: target.findingId,
        description: target.description,
        sanitizer_output: sanitizerOutput,
        behavioral_proof: behavioralProof,
        proof_detail: proofDetail,
        boot: this.config.boot,
        healthcheck: this.config.healthcheck,
        egress_allowlist: this.config.egress_allowlist,
        firecracker: this.config.firecracker
      })
    });
  }

  runs() {
    return this.request<Run[]>("/runs");
  }

  run(id: string) {
    return this.request<Run>(`/runs/${id}`);
  }

  cancelRun(id: string) {
    return this.request<Run>(`/runs/${id}/cancel`, { method: "POST" });
  }

  async trace(id: string) {
    const response = await fetch(`${this.config.apiUrl}/runs/${id}/trace`, {
      headers: await this.authHeaders()
    });
    if (!response.ok) {
      throw new Error(`${response.status} ${response.statusText}: ${await response.text()}`);
    }
    return response.text();
  }

  async *runEvents(id: string): AsyncGenerator<string> {
    const response = await fetch(`${this.config.apiUrl}/runs/${id}/events`, {
      headers: await this.authHeaders()
    });
    if (!response.ok || !response.body) {
      throw new Error(`${response.status} ${response.statusText}: ${await response.text()}`);
    }
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let boundary = buffer.indexOf("\n\n");
      while (boundary >= 0) {
        const chunk = buffer.slice(0, boundary);
        buffer = buffer.slice(boundary + 2);
        for (const line of chunk.split("\n")) {
          if (line.startsWith("data: ")) {
            yield line.slice("data: ".length);
          }
        }
        boundary = buffer.indexOf("\n\n");
      }
    }
  }
}
