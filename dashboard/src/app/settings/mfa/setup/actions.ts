"use server";

import { redirect } from "next/navigation";
import { mfaConfirm } from "../../../../lib/api";

export async function confirmMfaSetupAction(formData: FormData) {
  const code = String(formData.get("code") ?? "").trim();
  if (!code) {
    redirect(`/team/mfa/setup?error=${encodeURIComponent("Enter the 6-digit code")}`);
  }

  try {
    await mfaConfirm(code);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Invalid code";
    redirect(`/team/mfa/setup?error=${encodeURIComponent(message)}`);
  }

  redirect("/team?mfa=enabled");
}
