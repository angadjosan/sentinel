/**
 * Valid TypeScript fixture: known structure for parse and resolution pass tests.
 *
 * Expected parse output:
 *   - FILE node
 *   - FUNCTION nodes: validateJWT, createUser, hashPassword, _extractClaims
 *   - CLASS node: AuthService
 *   - PARAMETER nodes on each function
 */

import * as crypto from "crypto";

export class AuthService {
  constructor(private readonly db: { query: (sql: string, params: unknown[]) => Promise<unknown[]> }) {}

  async validateJWT(token: string): Promise<{ userId: string } | null> {
    const claims = _extractClaims(token);
    if (!claims) return null;
    return { userId: claims.sub };
  }

  async createUser(email: string, password: string): Promise<string> {
    const hashed = hashPassword(password);
    const rows = await this.db.query(
      "INSERT INTO users (email, password_hash) VALUES (?, ?) RETURNING id",
      [email, hashed]
    );
    return (rows[0] as { id: string }).id;
  }
}

export function hashPassword(password: string): string {
  return crypto.createHash("sha256").update(password).digest("hex");
}

function _extractClaims(token: string): { sub: string } | null {
  try {
    const [, payload] = token.split(".");
    return JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as { sub: string };
  } catch {
    return null;
  }
}
