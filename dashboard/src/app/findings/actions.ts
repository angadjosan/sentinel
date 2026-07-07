"use server";

import { revalidatePath } from "next/cache";
import { approveSuppression, rejectSuppression, suppressFinding } from "../../lib/api";

export async function suppressFindingAction(id: string): Promise<void> {
  await suppressFinding(id, "Reviewed in dashboard");
  revalidatePath("/findings");
}

export async function approveSuppressionAction(id: string): Promise<void> {
  await approveSuppression(id, "Approved in dashboard");
  revalidatePath("/findings");
}

export async function rejectSuppressionAction(id: string): Promise<void> {
  await rejectSuppression(id, "Rejected in dashboard");
  revalidatePath("/findings");
}
