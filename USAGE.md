# Sentinel — Usage Guide

## Install

```bash
pip install sentinel-sec
```

Requires Python 3.11+.

---

## CLI Quick Start

```bash
# Dep scan only (no API key needed)
sentinel scan --repo owner/repo --module deps

# Full scan — deps + LLM code security review
ANTHROPIC_API_KEY=sk-ant-... sentinel scan --repo owner/repo

# Full scan including attack surface
ANTHROPIC_API_KEY=sk-ant-... sentinel scan --repo owner/repo --module deps --module code --module surface

# Scan a specific PR
ANTHROPIC_API_KEY=sk-ant-... sentinel scan --repo owner/repo --pr 142

# CI mode — no Rich UI, no dashboard, exit 1 on high+ findings
sentinel scan --repo owner/repo --quiet --fail-on high

# Open the dashboard against a saved report
sentinel dashboard --report ./sentinel-report/findings.json
```

Accepts repo as `owner/repo`, `https://github.com/owner/repo`, or `git@github.com:owner/repo.git`.

---

## Configuration

Create `sentinel.yml` in your project root (or `~/.config/sentinel/sentinel.yml` for a global default):

```yaml
anthropic_api_key: sk-ant-...    # or set ANTHROPIC_API_KEY env var
github_token: ghp_...            # optional — for private repos
output_dir: ./sentinel-report
fail_on: high                    # critical | high | medium | low | never
dashboard_port: 4000
dashboard_auto_open: true
```

Environment variables take precedence over `sentinel.yml`.

| Env var | Purpose |
|---------|---------|
| `ANTHROPIC_API_KEY` | Required for code security module |
| `GITHUB_TOKEN` | Private repo access, higher rate limits |
| `REDIS_URL` | Celery broker (server mode, default: `redis://localhost:6379/0`) |
| `GITHUB_APP_ID` | GitHub App ID (server mode) |
| `GITHUB_APP_PRIVATE_KEY` | GitHub App RSA private key PEM or base64 |
| `GITHUB_WEBHOOK_SECRET` | Webhook HMAC secret (server mode) |
| `DATABASE_URL` | Postgres connection string (server mode) |

---

## Modules

| Module | Flag | What it does | Requires |
|--------|------|--------------|----------|
| **deps** | `--module deps` | Scans dep files for CVEs via OSV.dev, scores by CVSS | Nothing |
| **code** | `--module code` | LLM semantic security review of recent commits or a PR diff | `ANTHROPIC_API_KEY` |
| **surface** | `--module surface` | DNS/TLS/dangling CNAME enumeration from repo domain references | Nothing |

Default: `deps` + `code`.

---

## Output

After a scan, `./sentinel-report/findings.json` contains the full report:

```json
{
  "scan_id": "...",
  "repo": "https://github.com/owner/repo",
  "timestamp": "2026-04-15T...",
  "risk_score": 42,
  "dep_findings": [...],
  "code_security_findings": [...],
  "attack_surface_findings": [...]
}
```

View it in the terminal:

```bash
sentinel show ./sentinel-report/findings.json
```

Or in the browser:

```bash
sentinel dashboard --report ./sentinel-report/findings.json
# opens http://localhost:4000
```

---

## Dashboard

The dashboard is a Next.js app in `dashboard/`. First run builds it automatically when you run `sentinel dashboard`. To build manually:

```bash
cd dashboard
npm install
npm run build
```

---

## GitHub App (Server Mode)

For automatic PR reviews on every push, deploy Sentinel as a GitHub App.

### 1. Create the GitHub App

Go to **github.com/settings/apps → New GitHub App** and set:

- **Webhook URL**: `https://your-api.railway.app/webhooks/github`
- **Webhook secret**: any random string → set as `GITHUB_WEBHOOK_SECRET`
- **Permissions**: `Contents: read`, `Pull requests: write`, `Checks: write`, `Metadata: read`
- **Events**: `Push`, `Pull request`, `Installation`

Download the private key (`.pem` file).

### 2. Set environment variables

```bash
GITHUB_APP_ID=123456
GITHUB_APP_PRIVATE_KEY="$(cat your-app.pem)"   # or base64-encode it
GITHUB_WEBHOOK_SECRET=your-secret
ANTHROPIC_API_KEY=sk-ant-...
REDIS_URL=redis://...
DATABASE_URL=postgresql://...
```

### 3. Deploy to Railway

```bash
railway login
railway up
```

The `railway.toml` defines three services:
- `api` — FastAPI webhook receiver
- `worker-high` — Celery worker for PR reviews (high priority)
- `worker-default` — Celery worker for dep + surface scans

### 4. Install the App

Go to your GitHub App page → **Install App** → select your org or repo.

Sentinel will run a full baseline scan on install, then automatically review every PR.

---

## CI Integration

Add to `.github/workflows/sentinel.yml`:

```yaml
name: Sentinel Security Scan
on: [pull_request]

jobs:
  sentinel:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install sentinel-sec
      - run: sentinel scan --repo ${{ github.repository }} --pr ${{ github.event.pull_request.number }} --quiet --fail-on high
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

---

## Database Migrations

```bash
# Apply migrations to your Postgres DB
DATABASE_URL=postgresql://... alembic -c migrations/alembic.ini upgrade head
```
