// Bun build driver: produces ./binaries/sentinel-<os>-<arch>
// Run with: bun build.ts
import { mkdir } from "node:fs/promises";
import { BUILD_TARGETS } from "./src/build-targets.js";

await mkdir("binaries", { recursive: true });

for (const t of BUILD_TARGETS) {
  const proc = Bun.spawnSync([
    "bun", "build", "src/index.ts",
    "--compile",
    "--target", t.bunTarget,
    "--external", "keytar",
    "--outfile", `binaries/${t.asset}`,
  ], { stdout: "inherit", stderr: "inherit" });
  if (proc.exitCode !== 0) throw new Error(`build failed for ${t.bunTarget}`);
}
