// Adapter coverage warnings (AUDIT.md §6 W4 P5.4).
//
// The local scan engine records which changed files a framework adapter
// (Express, FastAPI, Django, Rails, Spring, Next.js, ...) recognized, and which
// it did not, in an `adapter.coverage` trace event. Files with no adapter match
// have no HTTP entry points / route guards extracted, so downstream reachability
// and pentest targeting are weaker for them. Surfacing the unmatched files on
// stderr after a scan tells the user *why* coverage might be thin — without
// leaking source (only repo-relative paths are printed).

/**
 * Build the human-readable adapter-coverage warning for `unmatchedFiles`.
 * Returns `null` when there is nothing to warn about, so callers can skip
 * printing entirely.
 */
export function formatAdapterWarnings(unmatchedFiles: readonly string[]): string | null {
  const files = dedupeStableNonEmpty(unmatchedFiles);
  if (files.length === 0) return null;

  const noun = files.length === 1 ? "file" : "files";
  const lines = [
    `warning: no framework adapter matched ${files.length} changed ${noun} — ` +
      `HTTP entry points may be missing, so reachability/pentest targeting is weaker for:`,
    ...files.map((f) => `  - ${f}`),
    `hint: add a matching adapter (or list it under custom_adapters in sentinel.config) if these expose routes.`,
  ];
  return lines.join("\n");
}

/**
 * Write the adapter-coverage warning to stderr (never stdout — stdout carries
 * the machine-readable scan summary). No-op when there is nothing to warn about.
 * `write` is injectable for testing.
 */
export function printAdapterWarnings(
  unmatchedFiles: readonly string[] | undefined,
  write: (s: string) => void = (s) => process.stderr.write(s)
): void {
  const message = formatAdapterWarnings(unmatchedFiles ?? []);
  if (message !== null) write(message + "\n");
}

function dedupeStableNonEmpty(files: readonly string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const raw of files) {
    const f = typeof raw === "string" ? raw.trim() : "";
    if (!f || seen.has(f)) continue;
    seen.add(f);
    out.push(f);
  }
  return out;
}
