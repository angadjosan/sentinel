"use server";

import { redirect } from "next/navigation";
import { loginMfaRequest } from "../../../lib/api";
import { setSessionCookie } from "../../../lib/session";

export async function loginMfaAction(formData: FormData) {
  const challengeToken = String(formData.get("challenge_token") ?? "");
  const code = String(formData.get("code") ?? "").trim();
  const next = String(formData.get("next") ?? "/") || "/";

  if (!challengeToken) {
    redirect(`/login?error=${encodeURIComponent("Login session expired — log in again")}`);
  }

  if (!code) {
    redirect(
      `/login/mfa?challenge_token=${encodeURIComponent(challengeToken)}&next=${encodeURIComponent(next)}&error=${encodeURIComponent("Enter the 6-digit code")}`
    );
  }

  let token: string;
  try {
    const result = await loginMfaRequest({ challenge_token: challengeToken, code });
    token = result.access_token;
  } catch (error) {
    const message = error instanceof Error ? error.message : "Invalid code";
    redirect(
      `/login/mfa?challenge_token=${encodeURIComponent(challengeToken)}&next=${encodeURIComponent(next)}&error=${encodeURIComponent(message)}`
    );
  }

  await setSessionCookie(token);
  redirect(next);
}
