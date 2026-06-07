"use server";

import { revalidatePath } from "next/cache";
import { approveDeviceCode, updateAccountConfig } from "../../lib/api";

export async function updateAccountConfigAction(formData: FormData) {
  const provider = stringValue(formData.get("provider")) ?? "local";
  const model = stringValue(formData.get("model")) ?? "ollama";
  const apiEndpoint = stringValue(formData.get("api_endpoint"));
  const monthlyTokenBudget = optionalNumber(formData.get("monthly_token_budget"), "monthly token budget");
  const sourceRetentionDays = requiredNumber(formData.get("source_retention_days"), "source retention days");

  await updateAccountConfig({
    provider,
    model,
    api_endpoint: apiEndpoint,
    suppression_approval_required: formData.get("suppression_approval_required") === "on",
    monthly_token_budget: monthlyTokenBudget,
    source_retention_days: sourceRetentionDays
  });

  revalidatePath("/");
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
