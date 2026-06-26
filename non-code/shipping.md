# Shipping Guide

> **TODO:** Deploy the API to Vercel first (`vercel --prod` from repo root, set env vars per `non-code/DEPLOY.md`) — nothing below works until the cloud backend is live at a real URL.

## Publishing the npm CLI

`publish.yml` fires automatically on any `v*` tag pushed to the repo.

### Prerequisites

1. Set `NPM_TOKEN` as a GitHub repo secret (Settings → Secrets → Actions).
   - Create at npmjs.com → Access Tokens → Generate New Token → **Granular**, scoped to `sentinel-sec`, publish-only.

### Releasing a version

```bash
cd cli
npm version patch   # 0.1.0 → 0.1.1  (bug fixes)
npm version minor   # 0.1.0 → 0.2.0  (new features)
npm version major   # 0.1.0 → 1.0.0  (breaking changes)
git push origin main --tags
```

`npm version` bumps `cli/package.json`, creates a commit, and creates the tag. Pushing with `--tags` sends both the commit and the tag. `publish.yml` picks up the tag and runs `npm publish --provenance`.

No release branches needed — tag directly on main.

---

## GitHub App ("click install")

Users go to your GitHub App page, click **Install**, select repos, and Sentinel automatically runs on every PR — no workflow file, no npm, no config needed. It's how Dependabot, Snyk, and Codecov work.

Flow:
1. GitHub sends a `pull_request` webhook to your API when a PR opens or updates
2. Your API pulls the diff via GitHub API, runs the existing scan pipeline
3. Posts findings back as a GitHub **Check Run** (the green/red status block on the PR)

### Step 1 — Add the webhook endpoint to the API

Add to `api/sentinel_api/main.py`:

```python
import hmac, hashlib

@app.post("/webhook/github")
async def github_webhook(request: Request, db: AsyncSession = Depends(get_db)):
    # Verify signature
    secret = os.environ["GITHUB_APP_WEBHOOK_SECRET"].encode()
    sig = request.headers.get("x-hub-signature-256", "")
    body = await request.body()
    expected = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        raise HTTPException(status_code=401)

    payload = await request.json()
    event = request.headers.get("x-github-event")

    if event == "pull_request" and payload["action"] in ("opened", "synchronize"):
        pr = payload["pull_request"]
        installation_id = payload["installation"]["id"]
        repo_full_name = payload["repository"]["full_name"]
        head_sha = pr["head"]["sha"]
        base_sha = pr["base"]["sha"]

        # Create a pending check run
        token = await get_installation_token(installation_id)
        check_run_id = await create_check_run(token, repo_full_name, head_sha)

        # Enqueue the scan (reuse existing task queue)
        diff = await fetch_pr_diff(token, repo_full_name, pr["number"])
        task = await enqueue_task(db, repo_name=repo_full_name, kind="source",
            payload={"diff": diff, "run_context": "ci", "check_run_id": check_run_id,
                     "installation_id": installation_id, "repo": repo_full_name, "sha": head_sha})

    return {"ok": True}
```

Add three helper functions:

```python
async def get_installation_token(installation_id: int) -> str:
    """Exchange installation ID for a short-lived token using a JWT signed with the App private key."""
    import jwt, time
    app_id = os.environ["GITHUB_APP_ID"]
    private_key = os.environ["GITHUB_APP_PRIVATE_KEY"]  # PEM string
    now = int(time.time())
    payload = {"iat": now - 60, "exp": now + 600, "iss": app_id}
    app_jwt = jwt.encode(payload, private_key, algorithm="RS256")
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"https://api.github.com/app/installations/{installation_id}/access_tokens",
            headers={"Authorization": f"Bearer {app_jwt}", "Accept": "application/vnd.github+json"},
        )
        resp.raise_for_status()
        return resp.json()["token"]

async def create_check_run(token: str, repo: str, sha: str) -> int:
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"https://api.github.com/repos/{repo}/check-runs",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
            json={"name": "Sentinel Security Scan", "head_sha": sha, "status": "in_progress"},
        )
        resp.raise_for_status()
        return resp.json()["id"]

async def fetch_pr_diff(token: str, repo: str, pr_number: int) -> str:
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"https://api.github.com/repos/{repo}/pulls/{pr_number}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github.v3.diff"},
        )
        resp.raise_for_status()
        return resp.text
```

When the scan completes, update the check run with findings:

```python
async def complete_check_run(token: str, repo: str, check_run_id: int, findings: list):
    conclusion = "failure" if findings else "success"
    summary = f"{len(findings)} finding(s)" if findings else "No issues found"
    lines = [f"**{f['severity'].upper()}** {f['vuln_type']}: {f['title']}" for f in findings]
    async with httpx.AsyncClient() as client:
        await client.patch(
            f"https://api.github.com/repos/{repo}/check-runs/{check_run_id}",
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
            json={"status": "completed", "conclusion": conclusion,
                  "output": {"title": "Sentinel Security Scan", "summary": summary,
                             "text": "\n".join(lines)}},
        )
```

Call `complete_check_run` at the end of `execute_source_scan` when `check_run_id` is present in the task payload.

### Step 2 — Add env vars

| Variable | Value |
|---|---|
| `GITHUB_APP_ID` | From the App settings page |
| `GITHUB_APP_PRIVATE_KEY` | PEM private key generated in App settings |
| `GITHUB_APP_WEBHOOK_SECRET` | Random string set when creating the App |

### Step 3 — Create the GitHub App

1. Go to github.com/settings/apps → **New GitHub App**
2. Set:
   - **Webhook URL**: `https://your-api.vercel.app/webhook/github`
   - **Webhook secret**: same value as `GITHUB_APP_WEBHOOK_SECRET`
3. Set permissions:
   - Repository → **Contents**: Read
   - Repository → **Pull requests**: Read
   - Repository → **Checks**: Read & write
4. Subscribe to events: **Pull request**
5. Generate a private key and save it as `GITHUB_APP_PRIVATE_KEY`

### Step 4 — Publish to marketplace (optional)

In the App settings → Marketplace listing. Lets users find and install it from github.com/marketplace. Requires a logo, description, and pricing (free is fine).

Once published, users install with one click and Sentinel runs on every PR automatically — no CLI, no config, no workflow file.

---

## Both together

The npm CLI and the GitHub App are independent entry points to the same backend. Users can:
- Use the CLI locally for on-demand scans (`sentinel scan`)
- Use the GitHub App for automatic PR checks
- Use both simultaneously — findings from both appear in the same dashboard
