/**
 * TypeScript fixture that intentionally contains a syntax error.
 *
 * Expected parse output:
 *   - FILE node with parse_error=True
 *   - No FUNCTION nodes emitted
 */

// Deliberately malformed: missing closing brace on function body
export function brokenFunction(x: number, y: number): number {
  return x + y;
// missing closing brace intentionally omitted
