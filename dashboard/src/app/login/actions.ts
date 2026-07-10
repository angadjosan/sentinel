"use server";

import { redirect } from "next/navigation";
import { loginRequest } from "../../lib/api";
import { setSessionCookie } from "../../lib/session";

export async function loginAction(formData: FormData) {
  const email = String(formData.get("email") ?? "").trim();
  const password = String(formData.get("password") ?? "");
  const next = String(formData.get("next") ?? "/") || "/";

  if (!email || !password) {
    redirect(`/login?next=${encodeURIComponent(next)}&error=${encodeURIComponent("Email and password are required")}`);
  }

  let result: Awaited<ReturnType<typeof loginRequest>>;
  try {
    result = await loginRequest({ email, password });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Invalid email or password";
    redirect(`/login?next=${encodeURIComponent(next)}&error=${encodeURIComponent(message)}`);
  }

  if (result.mfa_required && result.challenge_token) {
    redirect(
      `/login/mfa?challenge_token=${encodeURIComponent(result.challenge_token)}&next=${encodeURIComponent(next)}`
    );
  }

  if (!result.access_token) {
    redirect(`/login?next=${encodeURIComponent(next)}&error=${encodeURIComponent("Invalid email or password")}`);
  }

  await setSessionCookie(result.access_token);
  redirect(next);
}
