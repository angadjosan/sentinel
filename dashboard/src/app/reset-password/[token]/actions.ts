"use server";

import { redirect } from "next/navigation";
import { resetPasswordRequest } from "../../../lib/api";

export async function resetPasswordAction(formData: FormData) {
  const token = String(formData.get("token") ?? "");
  const password = String(formData.get("password") ?? "");
  const confirmPassword = String(formData.get("confirm_password") ?? "");

  if (!token) {
    redirect(`/login?error=${encodeURIComponent("Reset link is invalid or expired")}`);
  }

  if (password.length < 8) {
    redirect(`/reset-password/${token}?error=${encodeURIComponent("Password must be at least 8 characters")}`);
  }

  if (password !== confirmPassword) {
    redirect(`/reset-password/${token}?error=${encodeURIComponent("Passwords do not match")}`);
  }

  try {
    await resetPasswordRequest({ token, password });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Could not reset password";
    redirect(`/reset-password/${token}?error=${encodeURIComponent(message)}`);
  }

  redirect("/login?reset=1");
}
