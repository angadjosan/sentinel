import { cookies } from "next/headers";
import { jwtVerify } from "jose";

export const SESSION_COOKIE = "sentinel_session";
const SESSION_MAX_AGE_SECONDS = 60 * 60 * 24 * 14; // mirrors DASHBOARD_SESSION_MINUTES on the API

export type SessionPrincipal = {
  userId: string;
  accountId: string;
  role: string;
};

export function isDevMode(): boolean {
  return process.env.SENTINEL_DEV_MODE === "1";
}

export async function getSessionToken(): Promise<string | undefined> {
  const store = await cookies();
  return store.get(SESSION_COOKIE)?.value;
}

export async function setSessionCookie(token: string): Promise<void> {
  const store = await cookies();
  store.set(SESSION_COOKIE, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: SESSION_MAX_AGE_SECONDS
  });
}

export async function clearSessionCookie(): Promise<void> {
  const store = await cookies();
  store.delete(SESSION_COOKIE);
}

export async function getSession(): Promise<SessionPrincipal | null> {
  if (isDevMode()) {
    return { userId: "dev", accountId: "dev", role: "admin" };
  }
  const token = await getSessionToken();
  const secret = process.env.SENTINEL_JWT_SECRET;
  if (!token || !secret) return null;
  try {
    const { payload } = await jwtVerify(token, new TextEncoder().encode(secret));
    return {
      userId: String(payload.sub),
      accountId: String(payload.account_id),
      role: String(payload.role ?? "readonly")
    };
  } catch {
    return null;
  }
}
