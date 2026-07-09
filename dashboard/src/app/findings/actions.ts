"use server";

import { revalidatePath } from "next/cache";
import { approveSuppression, rejectSuppression, suppressFinding } from "../../lib/api";

function requireReason(reason: string): string {
  const trimmed = reason.trim();
  if (trimmed.length < 10) {
    throw new Error("A suppression reason of at least 10 characters is required.");
  }
  return trimmed;
}

export async function suppressFindingAction(id: string, reason: string): Promise<void> {
  await suppressFinding(id, requireReason(reason));
  revalidatePath("/findings");
}

export async function approveSuppressionAction(id: string, reason: string): Promise<void> {
  await approveSuppression(id, requireReason(reason));
  revalidatePath("/findings");
}

export async function rejectSuppressionAction(id: string, reason: string): Promise<void> {
  await rejectSuppression(id, requireReason(reason));
  revalidatePath("/findings");
}
