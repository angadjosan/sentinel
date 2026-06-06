import { execFileSync } from "node:child_process";

export function git(args: string[]): string {
  return execFileSync("git", args, { encoding: "utf8" });
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
