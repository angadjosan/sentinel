"use server";

import { revalidatePath } from "next/cache";
import {
  approveDeviceCode,
  approveSuppression,
  createRepo,
  mfaDisable,
  rejectSuppression,
  resendVerificationEmail,
  revokeSession,
  reviewPlan,
  updateAccountConfig,
  updateRepoPentestConfig,
  type PentestMode,
  type RepoPentestConfigPatch
} from "../../lib/api";

export async function createRepoAction(formData: FormData) {
  const name = String(formData.get("name") ?? "").trim();
  if (!name) throw new Error("repository name is required");
  const remoteUrl = String(formData.get("remote_url") ?? "").trim() || null;
  await createRepo({ name, remote_url: remoteUrl });
  revalidatePath("/settings");
  revalidatePath("/", "layout");
}

export async function reviewPlanAction(repoId: string, content: string, withRetry: boolean): Promise<string> {
  if (!repoId) return "error: select a repository first";
  if (!content.trim()) return "error: paste a plan to review";
  try {
    const result = await reviewPlan(repoId, { content, with_retry: withRetry });
    return result.run.id;
  } catch (error) {
    return `error: ${error instanceof Error ? error.message : String(error)}`;
  }
}

export async function updateAccountConfigAction(formData: FormData) {
  // Partial patch — each Settings section submits only the fields it owns.
  // No api_key field: LLM keys are configured and used locally now
  // (`sentinel config set api-key`) — the server rejects one if sent.
  const patch: Parameters<typeof updateAccountConfig>[0] = {};
  if (formData.has("provider")) patch.provider = stringValue(formData.get("provider")) ?? "local";
  if (formData.has("model")) patch.model = stringValue(formData.get("model")) ?? "ollama";
  if (formData.has("api_endpoint")) patch.api_endpoint = stringValue(formData.get("api_endpoint"));
  if (formData.has("monthly_token_budget")) patch.monthly_token_budget = optionalNumber(formData.get("monthly_token_budget"), "monthly token budget");
  if (formData.has("source_retention_days")) patch.source_retention_days = requiredNumber(formData.get("source_retention_days"), "source retention days");
  if (formData.has("approval_present")) patch.suppression_approval_required = formData.get("suppression_approval_required") === "on";

  await updateAccountConfig(patch);

  revalidatePath("/");
  revalidatePath("/settings");
}

export async function updateRepoPentestConfigAction(formData: FormData) {
  const repoId = stringValue(formData.get("repo_id"));
  if (!repoId) throw new Error("repo_id is required");

  const mode = stringValue(formData.get("pentest_mode"));
  if (mode !== "staging" && mode !== "local_worker") {
    throw new Error("pentest_mode must be 'staging' or 'local_worker'");
  }
  const pentestMode = mode as PentestMode;

  const patch: RepoPentestConfigPatch = { pentest_mode: pentestMode };

  if (pentestMode === "staging") {
    // Local engine probes a reachable staging URL — no boot argv (§3 D1).
    const stagingBaseUrl = stringValue(formData.get("staging_base_url"));
    if (!stagingBaseUrl) {
      throw new Error("staging_base_url is required in staging mode");
    }
    patch.staging_base_url = stagingBaseUrl;
    patch.healthcheck_path = stringValue(formData.get("healthcheck_path"));
    // Clear self-hosted-only fields so the two modes don't bleed together.
    patch.boot = null;
    patch.healthcheck = null;
    patch.egress_allowlist = [];
  } else {
    // Local engine boots the app under a gVisor sandbox on the dev machine (§3 D1).
    patch.boot = stringValue(formData.get("boot"));
    patch.healthcheck = stringValue(formData.get("healthcheck"));
    patch.egress_allowlist = parseAllowlist(formData.get("egress_allowlist"));
    patch.staging_base_url = null;
    patch.healthcheck_path = null;
  }

  await updateRepoPentestConfig(repoId, patch);
  revalidatePath("/settings");
}

export async function approveSuppressionAction(formData: FormData) {
  const findingId = stringValue(formData.get("finding_id"));
  const reason = stringValue(formData.get("reason"));
  if (!findingId) throw new Error("finding_id is required");
  if (!reason) throw new Error("a suppression review reason is required");
  await approveSuppression(findingId, reason);
  revalidatePath("/settings");
}

export async function rejectSuppressionAction(formData: FormData) {
  const findingId = stringValue(formData.get("finding_id"));
  const reason = stringValue(formData.get("reason"));
  if (!findingId) throw new Error("finding_id is required");
  if (!reason) throw new Error("a suppression review reason is required");
  await rejectSuppression(findingId, reason);
  revalidatePath("/settings");
}

export async function approveDeviceCodeAction(formData: FormData) {
  const userCode = stringValue(formData.get("user_code"));
  if (userCode === null) {
    throw new Error("device code is required");
  }
  await approveDeviceCode(userCode.toUpperCase());
  revalidatePath("/settings");
}

export async function revokeSessionAction(formData: FormData) {
  const id = stringValue(formData.get("id"));
  if (!id) throw new Error("session id is required");
  await revokeSession(id);
  revalidatePath("/settings");
}

export async function resendVerificationAction() {
  await resendVerificationEmail();
  revalidatePath("/settings");
}

export async function mfaDisableAction(formData: FormData) {
  const password = stringValue(formData.get("password"));
  if (!password) throw new Error("password is required");
  await mfaDisable(password);
  revalidatePath("/settings");
}

function stringValue(value: FormDataEntryValue | null): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

function parseAllowlist(value: FormDataEntryValue | null): string[] {
  const text = stringValue(value);
  if (text === null) return [];
  return text
    .split(/[\n,]/)
    .map((host) => host.trim())
    .filter(Boolean);
}

function optionalNumber(value: FormDataEntryValue | null, label: string): number | null {
  const text = stringValue(value);
  if (text === null) return null;
  return parsePositiveNumber(text, label, 0);
}

function requiredNumber(value: FormDataEntryValue | null, label: string): number {
  const text = stringValue(value);
  if (text === null) {
    throw new Error(`${label} is required`);
  }
  return parsePositiveNumber(text, label, 1);
}

function parsePositiveNumber(value: string, label: string, minimum: number): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < minimum) {
    throw new Error(`${label} must be an integer greater than or equal to ${minimum}`);
  }
  return parsed;
}
