"use server";

import { revalidatePath } from "next/cache";
import {
  approveDeviceCode,
  approveSuppression,
  mfaDisable,
  rejectSuppression,
  resendVerificationEmail,
  revokeSession,
  updateAccountConfig
} from "../../lib/api";

export async function updateAccountConfigAction(formData: FormData) {
  const provider = stringValue(formData.get("provider")) ?? "local";
  const model = stringValue(formData.get("model")) ?? "ollama";
  const apiEndpoint = stringValue(formData.get("api_endpoint"));
  const monthlyTokenBudget = optionalNumber(formData.get("monthly_token_budget"), "monthly token budget");
  const sourceRetentionDays = requiredNumber(formData.get("source_retention_days"), "source retention days");

  // No api_key field: LLM keys are configured and used locally now
  // (`sentinel config set api-key`) — the server rejects one if sent.
  const patch: Parameters<typeof updateAccountConfig>[0] = {
    provider,
    model,
    api_endpoint: apiEndpoint,
    suppression_approval_required: formData.get("suppression_approval_required") === "on",
    monthly_token_budget: monthlyTokenBudget,
    source_retention_days: sourceRetentionDays
  };

  await updateAccountConfig(patch);

  revalidatePath("/");
  revalidatePath("/team");
}

export async function approveSuppressionAction(formData: FormData) {
  const findingId = stringValue(formData.get("finding_id"));
  const reason = stringValue(formData.get("reason")) ?? "Approved by admin";
  if (!findingId) throw new Error("finding_id is required");
  await approveSuppression(findingId, reason);
  revalidatePath("/team");
}

export async function rejectSuppressionAction(formData: FormData) {
  const findingId = stringValue(formData.get("finding_id"));
  const reason = stringValue(formData.get("reason")) ?? "Rejected by admin";
  if (!findingId) throw new Error("finding_id is required");
  await rejectSuppression(findingId, reason);
  revalidatePath("/team");
}

export async function approveDeviceCodeAction(formData: FormData) {
  const userCode = stringValue(formData.get("user_code"));
  if (userCode === null) {
    throw new Error("device code is required");
  }
  await approveDeviceCode(userCode.toUpperCase());
  revalidatePath("/team");
}

export async function revokeSessionAction(formData: FormData) {
  const id = stringValue(formData.get("id"));
  if (!id) throw new Error("session id is required");
  await revokeSession(id);
  revalidatePath("/team");
}

export async function resendVerificationAction() {
  await resendVerificationEmail();
  revalidatePath("/team");
}

export async function mfaDisableAction(formData: FormData) {
  const password = stringValue(formData.get("password"));
  if (!password) throw new Error("password is required");
  await mfaDisable(password);
  revalidatePath("/team");
}

function stringValue(value: FormDataEntryValue | null): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
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
