import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import type { NextConfig } from "next";

const dashboardDir = dirname(fileURLToPath(import.meta.url));

const nextConfig: NextConfig = {
  output: "standalone",
  outputFileTracingRoot: dashboardDir,
  env: {
    NEXT_PUBLIC_SENTINEL_API_URL: process.env.NEXT_PUBLIC_SENTINEL_API_URL ?? "http://localhost:8000"
  }
};

export default nextConfig;
