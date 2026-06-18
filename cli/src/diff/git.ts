import { execFileSync } from "node:child_process";

export function git(args: string[]): string {
  return execFileSync("git", args, { encoding: "utf8" });
}

export type DiffResult = { diff: string; label: string };

export function currentDiff(options: { staged?: boolean; base?: string; paths?: string[] } = {}): DiffResult {
  const pathArgs = options.paths?.length ? ["--", ...options.paths] : [];

  if (options.staged) {
    return { diff: git(["diff", "--staged", ...pathArgs]), label: "staged changes" };
  }
  if (options.base) {
    return { diff: git(["diff", `${options.base}..HEAD`, ...pathArgs]), label: `${options.base}..HEAD` };
  }

  // Default: all uncommitted changes (staged + unstaged) vs HEAD.
  const uncommitted = git(["diff", "HEAD", ...pathArgs]);
  if (uncommitted.trim()) return { diff: uncommitted, label: "uncommitted changes" };

  // Working tree is clean — scan the most recent commit instead.
  return { diff: git(["diff", "HEAD~1..HEAD", ...pathArgs]), label: "HEAD~1..HEAD  (working tree is clean)" };
}

export function lsFiles(): string[] {
  return git(["ls-files"]).split("\n").filter(Boolean);
}
