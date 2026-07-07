import { NextRequest, NextResponse } from "next/server";
import { jwtVerify } from "jose";

import { SESSION_COOKIE } from "./lib/session";

// Local self-host (SENTINEL_DEV_MODE=1) mirrors the API's own dev-mode bypass —
// no login required for `docker compose up -d`. Only the hosted/cloud backend
// (SENTINEL_DEV_MODE unset) gates the dashboard behind real auth.
//
// /login/mfa is covered by the "/login" prefix already. Everything else here
// is reachable by a signed-out browser by design: password reset and email
// verification links arrive with no session, and the GitHub OAuth round trip
// (Route Handlers, not pages) happens before a session cookie exists.
const PUBLIC_PREFIXES = ["/login", "/signup", "/forgot-password", "/reset-password", "/verify-email", "/auth/github"];

export async function middleware(request: NextRequest) {
  if (process.env.SENTINEL_DEV_MODE === "1") {
    return NextResponse.next();
  }

  const { pathname } = request.nextUrl;
  if (PUBLIC_PREFIXES.some((prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`))) {
    return NextResponse.next();
  }

  const token = request.cookies.get(SESSION_COOKIE)?.value;
  const secret = process.env.SENTINEL_JWT_SECRET;
  if (token && secret) {
    try {
      await jwtVerify(token, new TextEncoder().encode(secret));
      return NextResponse.next();
    } catch {
      // fall through to redirect
    }
  }

  const loginUrl = new URL("/login", request.url);
  loginUrl.searchParams.set("next", `${pathname}${request.nextUrl.search}`);
  return NextResponse.redirect(loginUrl);
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"]
};
