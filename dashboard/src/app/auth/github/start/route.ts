import { randomBytes } from "crypto";
import { NextRequest, NextResponse } from "next/server";

const STATE_COOKIE = "sentinel_oauth_state";
const GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize";

export async function GET(request: NextRequest) {
  const clientId = process.env.GITHUB_OAUTH_CLIENT_ID;
  const next = request.nextUrl.searchParams.get("next") ?? "/";

  if (!clientId) {
    return NextResponse.redirect(new URL(`/login?error=${encodeURIComponent("GitHub sign-in is not configured")}`, request.url));
  }

  const state = randomBytes(16).toString("hex");
  const redirectUri = new URL("/auth/github/callback", request.nextUrl.origin).toString();

  const authorizeUrl = new URL(GITHUB_AUTHORIZE_URL);
  authorizeUrl.searchParams.set("client_id", clientId);
  authorizeUrl.searchParams.set("redirect_uri", redirectUri);
  authorizeUrl.searchParams.set("scope", "read:user user:email");
  authorizeUrl.searchParams.set("state", state);

  const response = NextResponse.redirect(authorizeUrl);
  response.cookies.set(STATE_COOKIE, JSON.stringify({ state, next }), {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: 600
  });
  return response;
}
