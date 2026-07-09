"use server";

import { revalidatePath } from "next/cache";
import { approveSuppression, rejectSuppression, removeSuppression, startPentest, suppressFinding, unsuppressFinding } from "../../lib/api";

export async function suppressFindingAction(id: string): Promise<void> {
  await suppressFinding(id, "Reviewed in dashboard");
  revalidatePath("/findings");
}

export async function suppressWithReasonAction(id: string, reason: string): Promise<void> {
  await suppressFinding(id, reason || "Reviewed in dashboard");
  revalidatePath(`/findings/${id}`);
  revalidatePath("/findings");
}

export async function unsuppressFindingAction(id: string): Promise<void> {
  await removeSuppression(id).catch(async () => {
    await unsuppressFinding(id, "Reopened in dashboard");
  });
  revalidatePath(`/findings/${id}`);
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

export async function startPentestAction(findingId: string): Promise<string> {
  try {
    const result = await startPentest({ finding_id: findingId });
    revalidatePath(`/findings/${findingId}`);
    return result.run.id;
  } catch (error) {
    return `error: ${error instanceof Error ? error.message : String(error)}`;
  }
}
