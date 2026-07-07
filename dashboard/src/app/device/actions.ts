"use server";

import { redirect } from "next/navigation";
import { approveDeviceCode } from "../../lib/api";

export async function approveDeviceAction(formData: FormData) {
  const userCode = String(formData.get("user_code") ?? "").trim().toUpperCase();
  if (!userCode) throw new Error("user code is required");
  await approveDeviceCode(userCode);
  redirect(`/device?user_code=${encodeURIComponent(userCode)}&approved=1`);
}
