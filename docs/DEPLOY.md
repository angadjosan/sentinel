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
ghcr.io/angadjosan/sentinel-worker:latest
```

## Smoke Test

```bash
curl -fsSL https://your-api.vercel.app/health
```

Should return `200` with health JSON.
