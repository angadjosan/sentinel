import { execFileSync } from "node:child_process";

export function git(args: string[]): string {
  try {
    return execFileSync("git", args, { encoding: "utf8" });
  } catch (err) {
    const raw = err instanceof Error ? err.message : String(err);
    const detail = raw.replace(/\n/g, " ").trim();
    if (detail.includes("not a git repository")) {
      throw new Error("Not a git repository. Run `git init && git add . && git commit -m 'initial commit'` first.");
    }
    if (detail.includes("unknown revision") && args.some((a) => a.includes("HEAD~"))) {
      throw new Error(
        "Cannot diff HEAD~1 — this repo may have only one commit. " +
        "Use `sentinel source --base <ref>` or make at least one more commit."
      );
    }
    if (detail.includes("does not have any commits")) {
      throw new Error("This repository has no commits yet. Make an initial commit before running a scan.");
    }
    throw new Error(`Git error: ${detail}`);
  }
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
