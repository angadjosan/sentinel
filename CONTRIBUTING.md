# Contributing to Sentinel

Thanks for your interest in contributing. Before submitting a PR, please open an issue first to describe the bug or feature — this saves everyone time and ensures the work aligns with the project direction.

---

## Dev environment setup

**Requirements:** Python 3.11 or newer (tested on 3.11 and 3.12 in CI; **3.12** recommended), Git

```bash
# 1. Clone the repo
git clone https://github.com/angadjosan/sentinel.git
cd sentinel

# 2. Create a virtual environment
python -m venv .venv
source .venv/bin/activate

# 3. Install in editable mode with dev dependencies
pip install -e ".[dev]"

# 4. Set required env vars
cp .env.example .env
# Edit .env — at minimum set ANTHROPIC_API_KEY
```

---

## Running tests

```bash
pytest tests/ -v
```

For coverage:

```bash
pytest tests/ -v --cov=sentinel --cov-report=term-missing
```

---

## Linting and formatting

We use `ruff` for both linting and formatting.

```bash
# Check
ruff check .
ruff format --check .

# Auto-fix
ruff check --fix .
ruff format .
```

CI will fail on any lint errors, so run this before pushing.

---

## PR process

1. Fork the repo and create a branch: `git checkout -b feat/your-feature`
2. Make your changes, add tests
3. Run `pytest` and `ruff` locally — both must pass
4. Open a PR against `main` with a clear description of what changed and why
5. Link the related issue in the PR description

---

## Project structure

```
sentinel/
  cli/          # Click CLI entry points
  api/          # FastAPI app and webhook handlers
  worker/       # Celery tasks
  modules/
    surface/    # Attack surface enumeration
    deps/       # Dependency risk scoring
    auth/       # AI auth review
  models/       # Pydantic + SQLAlchemy models
  dashboard/    # Next.js frontend (separate package)
tests/
```
