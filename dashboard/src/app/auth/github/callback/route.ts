import { NextRequest, NextResponse } from "next/server";
import { githubOAuthLogin } from "../../../../lib/api";
import { setSessionCookie } from "../../../../lib/session";

const STATE_COOKIE = "sentinel_oauth_state";

export async function GET(request: NextRequest) {
  const code = request.nextUrl.searchParams.get("code");
  const state = request.nextUrl.searchParams.get("state");
  const stateCookie = request.cookies.get(STATE_COOKIE)?.value;

  const fail = (message: string) => {
    const response = NextResponse.redirect(new URL(`/login?error=${encodeURIComponent(message)}`, request.url));
    response.cookies.delete(STATE_COOKIE);
    return response;
  };

  if (!code || !state || !stateCookie) {
    return fail("GitHub sign-in failed — missing authorization response");
  }

  let saved: { state: string; next: string };
  try {
    saved = JSON.parse(stateCookie);
  } catch {
    return fail("GitHub sign-in failed — invalid state");
  }

  if (saved.state !== state) {
    return fail("GitHub sign-in failed — state mismatch");
  }

  const redirectUri = new URL("/auth/github/callback", request.nextUrl.origin).toString();

  let token: string;
  try {
    const result = await githubOAuthLogin({ code, redirect_uri: redirectUri });
    token = result.access_token;
  } catch (error) {
    const message = error instanceof Error ? error.message : "GitHub sign-in failed";
    return fail(message);
  }

  await setSessionCookie(token);
  const response = NextResponse.redirect(new URL(saved.next || "/", request.url));
  response.cookies.delete(STATE_COOKIE);
  return response;
}
