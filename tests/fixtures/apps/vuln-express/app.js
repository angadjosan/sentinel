/**
 * Intentionally vulnerable Express application for Sentinel end-to-end tests.
 *
 * Known vulnerabilities (ground truth for scanner tests):
 *  1. SQL injection in GET /users — user-controlled id injected directly into query string.
 *  2. Missing auth on POST /admin/reset — sibling routes use authMiddleware; this one does not.
 *  3. Hardcoded secret — AWS access key embedded in source.
 *
 * DO NOT deploy this application. It is a test fixture only.
 */

const express = require("express");
const Database = require("better-sqlite3");

const app = express();
app.use(express.json());

const db = new Database(":memory:");
db.prepare("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)").run();
db.prepare("INSERT INTO users VALUES (1, 'alice', 'alice@example.com')").run();
db.prepare("INSERT INTO users VALUES (2, 'bob', 'bob@example.com')").run();

// Hardcoded secret — picked up by secret scanning.
const AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLEFAKE1";
const AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

function authMiddleware(req, res, next) {
  const token = req.headers["authorization"];
  if (!token || token !== "Bearer supersecret") {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

// Protected routes — all use authMiddleware.
app.get("/profile", authMiddleware, (req, res) => {
  res.json({ name: "alice" });
});

app.get("/settings", authMiddleware, (req, res) => {
  res.json({ notifications: true });
});

// VULNERABILITY 1: SQL injection.
// req.query.id is injected directly into the SQL string without parameterization.
app.get("/users", authMiddleware, (req, res) => {
  const id = req.query.id;
  // sentinel-finding: sqli — id flows directly to query string
  const row = db.query(`SELECT * FROM users WHERE id = ${id}`);
  if (!row) return res.status(404).json({ error: "not found" });
  res.json(row);
});

// VULNERABILITY 2: Missing auth on an admin route.
// /admin/reset is missing authMiddleware while every sibling route above uses it.
app.post("/admin/reset", (req, res) => {
  db.prepare("DELETE FROM users").run();
  res.json({ ok: true });
});

// Safe parameterized query for comparison — should NOT produce a finding.
app.get("/users/safe", authMiddleware, (req, res) => {
  const id = req.query.id;
  const row = db.prepare("SELECT * FROM users WHERE id = ?").get(id);
  if (!row) return res.status(404).json({ error: "not found" });
  res.json(row);
});

app.get("/health", (_req, res) => res.json({ status: "ok" }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`vuln-express listening on ${PORT}`));

module.exports = app;
