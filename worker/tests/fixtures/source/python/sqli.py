"""Python fixture with a known SQL injection vulnerability.

Ground truth for end-to-end SAST scan tests:
  - Route: GET /search
  - Vulnerability: req parameter 'q' flows unsanitized to cursor.execute()
  - Expected finding: vuln_type='sqli', severity>='high'
  - Safe variant at /search/safe should NOT produce a finding.
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
    # VULNERABILITY: unsanitized 'q' injected into SQL string
    cursor.execute(f"SELECT * FROM products WHERE name LIKE '%{q}%'")
    rows = cursor.fetchall()
    return jsonify(rows)


@app.route("/search/safe")
def search_safe():
    q = request.args.get("q", "")
    conn = get_db()
    cursor = conn.cursor()
    # Safe: parameterized query
    cursor.execute("SELECT * FROM products WHERE name LIKE ?", (f"%{q}%",))
    rows = cursor.fetchall()
    return jsonify(rows)


@app.route("/health")
def health():
    return jsonify({"status": "ok"})
