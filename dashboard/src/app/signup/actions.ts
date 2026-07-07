"use server";

import { redirect } from "next/navigation";
import { signupRequest } from "../../lib/api";
import { setSessionCookie } from "../../lib/session";

export async function signupAction(formData: FormData) {
  const name = String(formData.get("name") ?? "").trim();
  const email = String(formData.get("email") ?? "").trim();
  const password = String(formData.get("password") ?? "");
  const accountName = String(formData.get("account_name") ?? "").trim();
  const next = String(formData.get("next") ?? "/") || "/";

  if (!name || !email || password.length < 8) {
    redirect(
      `/signup?next=${encodeURIComponent(next)}&error=${encodeURIComponent("Name, email, and an 8+ character password are required")}`
    );
  }

  let token: string;
  try {
    const result = await signupRequest({ name, email, password, account_name: accountName || undefined });
    token = result.access_token;
  } catch (error) {
    const message = error instanceof Error ? error.message : "Could not create account";
    redirect(`/signup?next=${encodeURIComponent(next)}&error=${encodeURIComponent(message)}`);
  }

  await setSessionCookie(token);
  redirect(next);
}
