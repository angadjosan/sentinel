# Sentinel Deployment Guide

## Architecture

The cloud backend (Vercel + Neon free tiers) is a thin coordination layer. Heavy compute (graph construction, LLM agent runs, pentest) runs **locally on the user's machine** via Docker, using the user's own LLM key.

## Prerequisites

- Vercel account (free tier)
- Neon account (free tier)
- GitHub account with the repo forked/cloned

## Step 1: Provision Neon Postgres

1. Create a free Neon project at [neon.tech](https://neon.tech)
2. Copy the **pooled connection string** (format: `postgresql+asyncpg://user:pass@ep-xxx.neon.tech/neondb`)

## Step 2: Deploy the API to Vercel

```bash
vercel --prod
```

Set these environment variables in Vercel (Settings → Environment Variables):

| Variable | Value |
|----------|-------|
| `DATABASE_URL` | Neon pooled connection string |
| `SENTINEL_WORKER_DATABASE_URL` | Same Neon connection string (issued to workers at login) |
| `SENTINEL_JWT_SECRET` | Generate: `python -c "import secrets; print(secrets.token_urlsafe(32))"` |
| `SENTINEL_DEV_MODE` | `0` |
| `CORS_ORIGINS` | `https://your-dashboard.vercel.app` |
| `GITHUB_APP_ID` | Only if using the GitHub App integration — see `non-code/shipping.md` |
| `GITHUB_APP_PRIVATE_KEY` | Only if using the GitHub App integration — see `non-code/shipping.md` |
| `GITHUB_APP_WEBHOOK_SECRET` | Only if using the GitHub App integration — see `non-code/shipping.md` |

After deploying, copy the production URL (e.g. `https://sentinel-api-xxx.vercel.app`).

## Step 3: Run migrations

Run once against Neon before first use:

```bash
DATABASE_URL="postgresql+asyncpg://..." python -m sentinel_worker.migrations
```

Or: the local worker auto-applies migrations on first run.

## Step 4: Deploy the Dashboard (optional)

The dashboard is a separate Next.js project in `dashboard/`. Deploy it as a separate Vercel project:

```bash
cd dashboard && vercel --prod
```

Set dashboard environment variable:
- `NEXT_PUBLIC_SENTINEL_API_URL`: your API URL from Step 2

## Step 5: Update CLI default

After deployment, update `cli/src/config/sentinel.config.ts` to set the `apiUrl` default to your production URL, then rebuild and publish a new release tag.

## Local Worker

Users install the CLI via curl and run `sentinel auth login`. At login, the CLI receives the Neon connection string and stores it locally. When a scan is triggered, `ensureBackend` launches the worker Docker container with the connection string and the user's LLM key injected as environment variables.

The worker image is published to GHCR on each release tag:
```
ghcr.io/sentineldev/sentinel-worker:latest
```

## Pentest sandbox worker (gVisor)

Only needed for **`local_worker`** pentest mode. The hosted default is
**`staging`** (HTTP probe of a running deployment) — it needs none of this, so the
Vercel API and the Railway worker are unchanged.

For `local_worker`, the worker boots the target under a **gVisor (`runsc`)**
sandbox with default-deny token-scoped egress, a credential broker, canaries, and
attack-safety controls. Migration `0005` (the `pentest_config` column) auto-applies
on worker/API boot — no manual migration step.

The worker image (`ghcr.io/<org>/sentinel-worker`) carries `docker` + `runsc` +
`iptables`. Pick one deployment shape:

**(a) Embedded daemon — self-contained, "runs wherever" privileged is allowed.**
```yaml
# docker-compose override for the worker service
privileged: true
environment:
  SENTINEL_EMBEDDED_DOCKER: "1"     # entrypoint starts dockerd + registers runsc
  SENTINEL_SANDBOX_RUNTIME: "auto"  # auto -> runsc if available, else runc
  SENTINEL_SANDBOX_HARD_EGRESS: "1" # apply iptables egress DROP (needs NET_ADMIN)
```

**(b) Host daemon — the VM host runs dockerd+runsc; the worker uses its socket.**
```bash
sudo ./scripts/install-gvisor.sh   # installs runsc, registers it, creates the network
```
```yaml
cap_add: ["NET_ADMIN"]
volumes: ["/var/run/docker.sock:/var/run/docker.sock"]
```

**Real upstream credentials** for the broker live only in the worker environment,
referenced by `credential_ref` → env var `SENTINEL_BROKER_<REF>` (e.g.
`SENTINEL_BROKER_STRIPE_TEST_KEY`). They never reach the agent or the target env.

**Graceful degradation:** if `runsc` is missing the worker falls back to `runc`
(still container + proxy isolated); if `NET_ADMIN` is missing it relies on the
internal network + proxy. If Docker itself is unavailable, `local_worker` tasks
fail preflight with a clear message — switch that repo to `staging`.

## Smoke Test

```bash
curl -fsSL https://your-api.vercel.app/health
```

Should return `200` with health JSON.

Sandbox worker image smoke (on a machine with Docker):
```bash
docker run --rm --entrypoint sh ghcr.io/<org>/sentinel-worker:latest -c "docker --version && runsc --version"
```
