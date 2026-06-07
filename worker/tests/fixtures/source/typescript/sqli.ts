/**
 * TypeScript fixture with a known SQL injection vulnerability.
 *
 * Ground truth for end-to-end SAST scan tests:
 *   - Route: GET /users
 *   - Vulnerability: req.query.id flows unsanitized to db.query()
 *   - Expected finding: vuln_type='sqli', severity>='high'
 *   - Safe variant at /users/safe should NOT produce a finding.
 */

import express from "express";

const app = express();

declare const db: {
  query: (sql: string) => Promise<unknown[]>;
  queryParam: (sql: string, params: unknown[]) => Promise<unknown[]>;
};

// VULNERABILITY: unsanitized req.query.id injected into SQL template literal
app.get("/users", async (req, res) => {
  const id = req.query.id as string;
  const rows = await db.query(`SELECT * FROM users WHERE id = ${id}`);
  res.json(rows);
});

// Safe: parameterized query — should NOT produce a finding
app.get("/users/safe", async (req, res) => {
  const id = req.query.id as string;
  const rows = await db.queryParam("SELECT * FROM users WHERE id = ?", [id]);
  res.json(rows);
});
