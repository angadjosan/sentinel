"use server";

import { redirect } from "next/navigation";
import { logoutRequest } from "../lib/api";
import { clearSessionCookie, isDevMode } from "../lib/session";

export async function logoutAction() {
  if (!isDevMode()) {
    await logoutRequest().catch(() => undefined);
  }
  await clearSessionCookie();
  redirect("/login");
}
