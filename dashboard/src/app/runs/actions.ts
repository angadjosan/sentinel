"use server";

import { revalidatePath } from "next/cache";
import { cancelRun } from "../../lib/api";

export async function cancelRunAction(formData: FormData) {
  const runId = String(formData.get("runId") ?? "");
  if (!runId) {
    throw new Error("runId is required");
  }
  await cancelRun(runId);
  revalidatePath("/runs");
  revalidatePath(`/runs/${runId}`);
}
