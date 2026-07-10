import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import type { NextConfig } from "next";

const dashboardDir = dirname(fileURLToPath(import.meta.url));

// Origin of the Sentinel FastAPI backend (the separate API project on Vercel).
// The rewrite below proxies `/api/*` here so the browser only ever talks to the
// dashboard's own origin — one domain, no CORS. Server-side code calls the API
// directly via SENTINEL_API_INTERNAL_URL and does not go through this proxy.
const apiOrigin = process.env.SENTINEL_API_ORIGIN ?? "http://localhost:8000";

const nextConfig: NextConfig = {
  output: "standalone",
  outputFileTracingRoot: dashboardDir,
  env: {
    NEXT_PUBLIC_SENTINEL_API_URL: process.env.NEXT_PUBLIC_SENTINEL_API_URL ?? "http://localhost:8000"
  },
  async rewrites() {
    // Browser requests to `/api/<path>` → `<apiOrigin>/<path>`. The API serves its
    // routes at the root (e.g. `/findings`), so the `/api` prefix is stripped here.
    return [{ source: "/api/:path*", destination: `${apiOrigin}/:path*` }];
  }
};

export default nextConfig;
