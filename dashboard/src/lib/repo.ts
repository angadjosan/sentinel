import { cookies } from "next/headers";

export const REPO_COOKIE = "sentinel_repo";

/** The repo name the user has scoped the dashboard to, if any. */
export async function getSelectedRepo(): Promise<string | null> {
  const store = await cookies();
  return store.get(REPO_COOKIE)?.value ?? null;
}

export async function setSelectedRepoCookie(name: string): Promise<void> {
  const store = await cookies();
  if (!name) {
    store.delete(REPO_COOKIE);
    return;
  }
  store.set(REPO_COOKIE, name, {
    path: "/",
    sameSite: "lax",
    maxAge: 60 * 60 * 24 * 365
  });
}
