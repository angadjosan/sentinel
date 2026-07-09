import { loadConfig, SentinelConfig } from "../config/sentinel.config.js";
import { readApiKey, readCredential, writeCredential } from "../auth/keychain.js";

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

export type EnqueueResponse = {
  task_id: string;
  run: Run;
};

// AUDIT.md §3 D1 — Repo pentest reachability config (dual mode). These field
// names are the locked D1 contract; the cloud stores them on the Repo and the
// worker (W1) reads them to decide how to reach the target app.
export type PentestMode = "staging" | "local_worker";

export type RepoPentestConfig = {
  repo_id: string;
  pentest_mode: PentestMode;
  staging_base_url?: string | null;
  healthcheck_path?: string | null;
  boot?: string | null;
  healthcheck?: string | null;
  egress_allowlist: string[];
  pentest_config?: Record<string, unknown> | null;
};

export type RepoPentestConfigPatch = {
  pentest_mode?: PentestMode;
  staging_base_url?: string | null;
  healthcheck_path?: string | null;
  boot?: string | null;
  healthcheck?: string | null;
  egress_allowlist?: string[];
  pentest_config?: Record<string, unknown> | null;
};

export type EnqueuePentestOptions = {
  findingId?: string;
  description?: string;
  sanitizerOutput?: string;
  behavioralProof?: string;
  proofDetail?: string;
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
      refresh_token?: string;
      expires_in?: number;
      account_id: string;
      user_id: string;
      database_url?: string;
    };

const DEFAULT_TIMEOUT_MS = 10_000;
const LONG_TIMEOUT_MS = 60_000;

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

  /** Exchange the stored refresh token for a fresh access+refresh pair. Returns false if there's nothing to refresh or the server rejects it. */
  private async refreshCredential(): Promise<boolean> {
    const credential = await readCredential(this.config);
    if (!credential?.refreshToken) return false;
    try {
      const response = await fetch(`${this.config.apiUrl}/auth/refresh`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refresh_token: credential.refreshToken }),
      });
      if (!response.ok) return false;
      const body = (await response.json()) as { access_token: string; refresh_token: string };
      await writeCredential(this.config, { accessToken: body.access_token, refreshToken: body.refresh_token });
      return true;
    } catch {
      return false;
    }
  }

  async request<T>(path: string, init: RequestInit = {}, timeoutMs?: number, _isRetry = false): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(
      () => controller.abort(),
      timeoutMs ?? this.requestTimeoutMs()
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
      // CLI access tokens are short-lived (1h) by design — a 401 here usually
      // just means it expired, so refresh once and retry transparently rather
      // than forcing the user through `sentinel auth login` again.
      if (response.status === 401 && !_isRetry && path !== "/auth/refresh" && (await this.refreshCredential())) {
        return this.request<T>(path, init, timeoutMs, true);
      }
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

  whoami() {
    return this.request<{
      id: string;
      email: string;
      name: string | null;
      role: string;
      account_id: string;
      account_name: string;
    }>("/auth/me");
  }

  logout() {
    return this.request<{ status: string }>("/auth/logout", { method: "POST" });
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
    }>(`/findings/${id}/pull`, {}, LONG_TIMEOUT_MS);
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

  /**
   * Enqueue a cloud pentest for a finding (AUDIT.md §3 D4 — CLI pentest is
   * enqueue + poll; execution happens on the cloud worker, never locally).
   * Returns the created task id and its run so the caller can poll to terminal.
   */
  enqueuePentest(options: EnqueuePentestOptions) {
    const body: Record<string, unknown> = { repo_name: this.config.repoName };
    if (options.findingId) body.finding_id = options.findingId;
    if (options.description) body.description = options.description;
    if (options.sanitizerOutput) body.sanitizer_output = options.sanitizerOutput;
    if (options.behavioralProof) body.behavioral_proof = options.behavioralProof;
    if (options.proofDetail) body.proof_detail = options.proofDetail;
    return this.request<EnqueueResponse>("/pentest", {
      method: "POST",
      body: JSON.stringify(body),
    });
  }

  /** Read a repo's cloud pentest reachability config (AUDIT.md §3 D1). */
  getPentestConfig(repoId: string) {
    return this.request<RepoPentestConfig>(`/repos/${repoId}/pentest-config`);
  }

  /** Sync a repo's cloud pentest reachability config (AUDIT.md §3 D1 / P1.4). */
  patchPentestConfig(repoId: string, patch: RepoPentestConfigPatch) {
    return this.request<RepoPentestConfig>(`/repos/${repoId}/pentest-config`, {
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
    const deadline = Date.now() + timeoutMs;
    const emitted = new Set<string>();
    const terminal = new Set(["completed", "failed", "cancelled"]);
    while (Date.now() < deadline) {
      const run = await this.run(id);
      for (const line of (run.trace ?? "").split("\n")) {
        const t = line.trim();
        if (t && !emitted.has(t)) {
          emitted.add(t);
          yield t;
        }
      }
      if (terminal.has(run.status)) return;
      await new Promise<void>((r) => setTimeout(r, 1000));
    }
  }
}
