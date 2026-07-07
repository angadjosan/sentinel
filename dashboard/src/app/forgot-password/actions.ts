"use server";

import { redirect } from "next/navigation";
import { forgotPasswordRequest } from "../../lib/api";

export async function forgotPasswordAction(formData: FormData) {
  const email = String(formData.get("email") ?? "").trim();
  if (!email) {
    redirect(`/forgot-password?error=${encodeURIComponent("Email is required")}`);
  }

  await forgotPasswordRequest(email).catch(() => undefined);
  redirect("/forgot-password?sent=1");
}
