import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import type { NextConfig } from "next";

const dashboardDir = dirname(fileURLToPath(import.meta.url));

// Single-domain deployment: the dashboard serves `/` and proxies `/api/*` to the
// API project. Browsers therefore only ever see one origin, so the session
// cookie is first-party on both the UI and the API and CORS never applies.
// SENTINEL_API_ORIGIN is the API's public base URL (no trailing slash).
const apiOrigin = process.env.SENTINEL_API_ORIGIN?.replace(/\/$/, "");

const nextConfig: NextConfig = {
  output: "standalone",
  outputFileTracingRoot: dashboardDir,
  env: {
    NEXT_PUBLIC_SENTINEL_API_URL: process.env.NEXT_PUBLIC_SENTINEL_API_URL ?? "http://localhost:8000"
  },
  async rewrites() {
    if (!apiOrigin) return [];
    return [{ source: "/api/:path*", destination: `${apiOrigin}/:path*` }];
  }
};

export default nextConfig;
