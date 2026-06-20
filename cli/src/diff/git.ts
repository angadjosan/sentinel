import { execFileSync } from "node:child_process";

export function git(args: string[]): string {
  try {
    return execFileSync("git", args, {
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024, // 64 MB for large diffs
    }).trimEnd();
  } catch (error: any) {
    if (error.code === "ENOENT") {
      throw new Error("git is not installed or not on PATH.");
    }
    const stderr: string = error.stderr ?? "";
    if (stderr.includes("not a git repository")) {
      throw new Error("Not a git repository. Run sentinel commands from inside your repo.");
    }
    throw error;
  }
}

export function currentDiff(options: { staged?: boolean; base?: string; paths?: string[] } = {}): string {
  const args = ["diff"];
  if (options.staged) args.push("--staged");
  if (options.base) args.push(`${options.base}..HEAD`);
  if (options.paths?.length) args.push("--", ...options.paths);
  return git(args);
}

export function lsFiles(): string[] {
  return git(["ls-files"]).split("\n").filter(Boolean);
}
