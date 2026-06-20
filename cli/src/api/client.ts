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
  file?: string | null;
  line_start?: number | null;
  line_end?: number | null;
  created_at: string;
  updated_at: string;
};

export type Run = {
  id: string;
  kind: string;
  status: string;
  finding_count: number;
  token_spend: number;
  model_used?: string | null;
  trace: string;
  created_at: string;
  completed_at?: string | null;
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

const DEFAULT_TIMEOUT_MS = 10_000;

export class SentinelApiClient {
  constructor(private readonly config: SentinelConfig = loadConfig()) {}

  private requestTimeoutMs(): number {
    return DEFAULT_TIMEOUT_MS;
  }

  private async authHeaders(): Promise<Record<string, string>> {
    const token = await readApiKey(this.config);
    return token ? { Authorization: `Bearer ${token}` } : {};
  }

  private wrapFetchError(error: unknown, apiUrl: string, path: string): never {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw new Error(
        `Request to ${apiUrl}${path} timed out after ${this.requestTimeoutMs() / 1000}s. ` +
          `Is the backend running? Start it with 'sentinel up'.`
      );
    }
    if (
      error instanceof TypeError &&
      (error as any).cause?.code === "ECONNREFUSED"
    ) {
      throw new Error(
        `Cannot reach Sentinel backend at ${apiUrl}. ` +
          `Start it with 'sentinel up' or set a different URL: 'sentinel config set apiUrl <url>'.`
      );
    }
    throw error;
  }

  async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(
      () => controller.abort(),
      this.requestTimeoutMs()
    );
    try {
      const response = await fetch(`${this.config.apiUrl}${path}`, {
        ...init,
        signal: controller.signal,
        headers: {
          "Content-Type": "application/json",
          ...(await this.authHeaders()),
          ...(init.headers ?? {}),
        },
      });
      if (!response.ok) {
        const detail = await response.text();
        throw new Error(`${response.status} ${response.statusText}: ${detail}`);
      }
      return response.json() as Promise<T>;
    } catch (error) {
      this.wrapFetchError(error, this.config.apiUrl, path);
    } finally {
      clearTimeout(timer);
    }
  }

  init(files: Record<string, string>) {
    return this.request<Run>("/init", {
      method: "POST",
      body: JSON.stringify({ repo_name: this.config.repoName, files }),
    });
  }

  startDeviceAuth() {
    return this.request<DeviceAuthStart>("/auth/device", { method: "POST" });
  }

  async deviceAuthToken(deviceCode: string): Promise<DeviceAuthToken> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.requestTimeoutMs());
    try {
      const response = await fetch(
        `${this.config.apiUrl}/auth/device/token?device_code=${encodeURIComponent(deviceCode)}`,
        { signal: controller.signal, headers: await this.authHeaders() }
      );
      if (response.status === 202) {
        return { status: "pending" };
      }
      if (!response.ok) {
        throw new Error(
          `${response.status} ${response.statusText}: ${await response.text()}`
        );
      }
      const body = (await response.json()) as Omit<
        Extract<DeviceAuthToken, { status: "approved" }>,
        "status"
      >;
      return { status: "approved", ...body };
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") {
        // On timeout during polling, return pending so the poll loop continues
        return { status: "pending" };
      }
      this.wrapFetchError(error, this.config.apiUrl, "/auth/device/token");
    } finally {
      clearTimeout(timer);
    }
  }

  source(
    diff: string,
    runContext: string,
    scope: { baseRef?: string; paths?: string[] } = {}
  ) {
    return this.request<{ run: Run; findings: Finding[] }>("/source", {
      method: "POST",
      body: JSON.stringify({
        repo_name: this.config.repoName,
        diff,
        run_context: runContext,
        base_ref: scope.baseRef,
        paths: scope.paths ?? [],
      }),
    });
  }

  enqueueSource(
    diff: string,
    runContext: string,
    scope: { baseRef?: string; paths?: string[] } = {}
  ) {
    return this.request<{ task_id: string; run: Run }>("/source/enqueue", {
      method: "POST",
      body: JSON.stringify({
        repo_name: this.config.repoName,
        diff,
        run_context: runContext,
        base_ref: scope.baseRef,
        paths: scope.paths ?? [],
      }),
    });
  }

  findings(filters: { status?: string; severity?: string } = {}) {
    const params = new URLSearchParams({ repo_name: this.config.repoName });
    if (filters.status) params.set("status", filters.status);
    if (filters.severity) params.set("severity", filters.severity);
    return this.request<Finding[]>(`/findings?${params.toString()}`);
  }

  finding(id: string) {
    return this.request<Finding>(`/findings/${id}`);
  }

  pull(id: string) {
    return this.request<{
      finding: Finding;
      node: unknown;
      remediation_plan: string[];
    }>(`/findings/${id}/pull`);
  }

  plan(content: string, withRetry: boolean) {
    return this.request<{ run: Run; findings: Finding[] }>("/plan", {
      method: "POST",
      body: JSON.stringify({
        repo_name: this.config.repoName,
        content,
        with_retry: withRetry,
      }),
    });
  }

  suppress(id: string, reason: string) {
    return this.request<Finding>(`/findings/${id}/suppress`, {
      method: "PATCH",
      body: JSON.stringify({ reason }),
    });
  }

  unsuppress(id: string, reason: string) {
    return this.request<Finding>(`/findings/${id}/unsuppress`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    });
  }

  approveSuppression(id: string, reason: string) {
    return this.request<Finding>(`/findings/${id}/suppress/approve`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    });
  }

  rejectSuppression(id: string, reason: string) {
    return this.request<Finding>(`/findings/${id}/suppress/reject`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    });
  }

  pentest(
    target: { findingId?: string; description?: string } = {},
    sanitizerOutput = "",
    behavioralProof?: string,
    proofDetail = ""
  ) {
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
        firecracker: this.config.firecracker,
      }),
    });
  }

  patchConfig(patch: {
    provider?: string;
    model?: string;
    api_key?: string;
    api_endpoint?: string | null;
  }) {
    return this.request<{
      account_id: string;
      provider: string;
      model: string;
    }>("/config", {
      method: "PATCH",
      body: JSON.stringify(patch),
    });
  }

  runs() {
    return this.request<Run[]>("/runs");
  }

  run(id: string) {
    return this.request<Run>(`/runs/${id}`);
  }

  cancelRun(id: string) {
    return this.request<Run>(`/runs/${id}`, { method: "DELETE" });
  }

  async trace(id: string): Promise<string> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.requestTimeoutMs());
    try {
      const response = await fetch(
        `${this.config.apiUrl}/runs/${id}/trace`,
        { signal: controller.signal, headers: await this.authHeaders() }
      );
      if (!response.ok) {
        throw new Error(
          `${response.status} ${response.statusText}: ${await response.text()}`
        );
      }
      return response.text();
    } catch (error) {
      this.wrapFetchError(error, this.config.apiUrl, `/runs/${id}/trace`);
    } finally {
      clearTimeout(timer);
    }
  }

  async *runEvents(id: string, timeoutMs = 120_000): AsyncGenerator<string> {
    const controller = new AbortController();
    // Overall wall-clock deadline for the entire stream
    const wallTimer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(
        `${this.config.apiUrl}/runs/${id}/events`,
        { signal: controller.signal, headers: await this.authHeaders() }
      );
      if (!response.ok || !response.body) {
        throw new Error(
          `${response.status} ${response.statusText}: ${await response.text()}`
        );
      }
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      let idleTimer: ReturnType<typeof setTimeout> | undefined;

      const resetIdle = () => {
        if (idleTimer) clearTimeout(idleTimer);
        // Abort if no data arrives for 30s
        idleTimer = setTimeout(() => controller.abort(), 30_000);
      };

      resetIdle();
      try {
        while (true) {
          const { value, done } = await reader.read();
          if (done) break;
          resetIdle();
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
      } finally {
        if (idleTimer) clearTimeout(idleTimer);
        reader.releaseLock();
      }
    } catch (error) {
      if (error instanceof DOMException && error.name === "AbortError") {
        // Stream ended due to timeout — caller handles gracefully
        return;
      }
      this.wrapFetchError(error, this.config.apiUrl, `/runs/${id}/events`);
    } finally {
      clearTimeout(wallTimer);
    }
  }
}
