# Troubleshooting

Common problems from a fresh clone or local demo run.

## Docker Compose port is already in use

Defaults:

- Web: `47000`
- API: `47080`
- Postgres: `47432`

Override in `.env`:

```env
WEB_PORT=48000
API_PORT=48080
POSTGRES_PORT=48432
```

Then rerun:

```bash
docker compose up --build
```

## Reset the demo database

```bash
docker compose down -v
docker compose up --build
```

This deletes Postgres data and uploaded source archives stored in Docker
volumes.

## Web build cannot resolve `@relix-q/web-components`

Build packages before the web app:

```bash
npm ci
npm run build:packages
npm run build:web
```

## `npm audit` reports a moderate PostCSS issue

The CI gate uses:

```bash
npm audit --omit=dev --audit-level=high
```

At the time of writing, `next@16.2.9` still carries a nested moderate PostCSS
advisory. High and critical production advisories are treated as blockers.

## Local path scan finds nothing

Local path projects scan the host folder mounted at `LOCAL_SCAN_PATH`, default
`./scan-targets`, inside the API container at `/scan`.

Put source under `scan-targets/` or set:

```env
LOCAL_SCAN_PATH=/absolute/path/to/repos
```

Then create a Local path project with the subfolder name, or leave it blank to
scan the whole mount.

## Upload scan fails

Zip source only. Exclude:

- `node_modules/`
- `.git/`
- build output
- large binary artifacts

The upload limit is 1 GB.

## Go scanner build uses regex floor only

A plain local `go build` gives regex plus pure-Go AST detectors. Full
tree-sitter AST requires `CGO_ENABLED=1` and a C toolchain. The Docker Compose
API image builds the scanner with CGO.

## GitHub secret scanning flags the validation corpus

`fixtures/validation-corpus/src/python/embedded_key.py` intentionally contains a
PEM private-key marker with no usable key body. It exists to test hardcoded-key
detection. The corpus README documents this boundary.

## Need more help

See [SUPPORT.md](../SUPPORT.md) for where to ask questions or report bugs.
