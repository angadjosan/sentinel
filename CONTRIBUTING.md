# Contributing to Sentinel

Sentinel is open source and we welcome contributions — new language grammars for the code graph, additional oracle types for the pentest layer, benchmark repos, and provider integrations are all high-value.

## Getting set up

```bash
git clone https://github.com/angadjosan/sentinel
cd sentinel
docker compose up -d          # backend (api + worker + db)
cd cli && npm install && npm run build && npm link   # CLI from source
```

Run `sentinel doctor` to confirm your environment is wired up correctly.

## Workflow

1. Open an issue first for anything beyond a small fix, so we can align on approach before you invest time.
2. Fork the repo and create a branch off `main`.
3. Make your change. Keep PRs focused — one logical change per PR is easier to review and land.
4. Add or update tests for the code you touch:
   - CLI (TypeScript): `cd cli && npm test`
   - API / worker (Python): `pytest` from the relevant package
5. Open a pull request against `main`. CI (lint, tests, and Sentinel's own self-scan) runs automatically.

## Code style

- TypeScript: formatted/linted per the CLI's existing `tsc`/lint config — run `npm run build` before submitting.
- Python: `ruff` + `mypy`, matching the existing `lint.yml` workflow.

## Licensing

By submitting a contribution, you agree it's licensed under the Apache License, Version 2.0 (see [LICENSE](LICENSE)), the same license as the rest of the project.
