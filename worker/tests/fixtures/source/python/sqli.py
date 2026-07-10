"""Python fixture with a known SQL injection vulnerability.

Ground truth for SAST scan tests (AUDIT.md §6 W4 P3.3):
  - Route: GET /search
  - Vulnerability: request parameter 'q' flows unsanitized into cursor.execute()
  - Expected finding: vuln_type='sqli', severity>='high'
  - Safe variant at /search/safe uses a parameterized query and must NOT
    produce a finding.

This file is read from disk by the SAST agent's `read_file` tool during a
scan; the test's LLM stub only emits a finding after it has actually read the
vulnerable line back through that tool boundary — it never regex-matches the
diff. That keeps the test honest: it fails if `read_file` / `emit_finding`
stop working, not merely if a regex stops matching.
"""
from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)


def get_db():
    return sqlite3.connect(":memory:")


@app.route("/search")
def search():
    q = request.args.get("q", "")
    conn = get_db()
    cursor = conn.cursor()
    # VULNERABILITY: unsanitized 'q' injected into the SQL string.
    cursor.execute(f"SELECT * FROM products WHERE name LIKE '%{q}%'")
    rows = cursor.fetchall()
    return jsonify(rows)


@app.route("/search/safe")
def search_safe():
    q = request.args.get("q", "")
    conn = get_db()
    cursor = conn.cursor()
    # Safe: parameterized query — bound parameter, no string interpolation.
    cursor.execute("SELECT * FROM products WHERE name LIKE ?", (f"%{q}%",))
    rows = cursor.fetchall()
    return jsonify(rows)


@app.route("/health")
def health():
    return jsonify({"status": "ok"})
