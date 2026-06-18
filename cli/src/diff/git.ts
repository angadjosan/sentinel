import { execFileSync } from "node:child_process";

export function git(args: string[]): string {
  return execFileSync("git", args, { encoding: "utf8" });
}

export function currentDiff(options: { staged?: boolean; base?: string; paths?: string[] } = {}): string {
  const pathArgs = options.paths?.length ? ["--", ...options.paths] : [];

  if (options.staged) {
    return git(["diff", "--staged", ...pathArgs]);
  }
  if (options.base) {
    return git(["diff", `${options.base}..HEAD`, ...pathArgs]);
  }

  // Default: all uncommitted changes (staged + unstaged) vs HEAD.
  // Falls back to the last commit diff if the working tree is clean.
  const uncommitted = git(["diff", "HEAD", ...pathArgs]);
  if (uncommitted.trim()) return uncommitted;

  // Working tree is clean — scan the most recent commit.
  return git(["diff", "HEAD~1..HEAD", ...pathArgs]);
}

export function lsFiles(): string[] {
  return git(["ls-files"]).split("\n").filter(Boolean);
}
