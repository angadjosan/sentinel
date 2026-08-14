# `@sentineldev/engine-<os>-<cpu>` — bundled Python analysis engine

These are the per-platform npm packages that let `npm install -g sentineldev`
work with **no separate `pip install`, no system Python**. Each contains a
PyInstaller-frozen (onedir) build of the Sentinel analysis engine
(`sentinel_worker.local_cli:main`). They mirror how `esbuild` / `@swc/core` /
`turbo` ship native binaries through npm optionalDependencies.

## How the CLI picks one

`sentineldev` lists all five as **optionalDependencies** (see `cli/package.json`).
npm installs only the package whose `os`/`cpu` fields match the host, so a mac
arm64 box gets just `@sentineldev/engine-darwin-arm64`. At runtime
`cli/src/engine/localEngine.ts::resolveEngineCommand()` resolves the installed
one via `require.resolve("@sentineldev/engine-<platform>-<arch>/bin/sentinel-local")`
and runs it directly. If none is installed it falls back to
`SENTINEL_ENGINE_BIN`, then to `python -m sentinel_worker.local_cli` (source/dev).

## Targets

| npm package                        | `os`    | `cpu`   | Runner            |
|------------------------------------|---------|---------|-------------------|
| `@sentineldev/engine-darwin-arm64` | darwin  | arm64   | macos-14          |
| `@sentineldev/engine-darwin-x64`   | darwin  | x64     | macos-13          |
| `@sentineldev/engine-linux-x64`    | linux   | x64     | ubuntu-latest     |
| `@sentineldev/engine-linux-arm64`  | linux   | arm64   | ubuntu-24.04-arm  |
| `@sentineldev/engine-win32-x64`    | win32   | x64     | windows-latest    |

## Package layout (built in CI, never committed)

```
@sentineldev/engine-darwin-arm64/
  package.json            # name, version, "os":["darwin"], "cpu":["arm64"]
  bin/
    sentinel-local        # PyInstaller launcher (sentinel-local.exe on win32)
    _internal/            # frozen CPython + deps + tree-sitter grammar .so/.dylib/.pyd
    sentinel_worker/prompts/*.txt
    alembic/versions/*.py
```

`bin/sentinel-local` is the onedir launcher; it must stay next to its
`_internal/` sibling (do not move it out on its own). `package.json` per target:

```jsonc
{
  "name": "@sentineldev/engine-darwin-arm64",
  "version": "0.2.0",
  "os": ["darwin"],
  "cpu": ["arm64"],
  "files": ["bin"]
}
```

## Building locally

```
worker/pyinstaller/build.sh        # freezes into worker/pyinstaller/dist/sentinel-local/
```

Then copy `worker/pyinstaller/dist/sentinel-local/` → the target package's `bin/`.
CI does this across the matrix in `.github/workflows/build-engine.yml`.

## Signing (CI-pending)

macOS builds must be **codesigned + notarized** and Windows builds **Authenticode
signed** before publish, or Gatekeeper/SmartScreen will block the frozen binary.
The workflow has these as commented TODO steps — no secrets are wired yet.
