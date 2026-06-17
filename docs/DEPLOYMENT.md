# Deployment

Relix-Q OSS has two primary deployment modes:

- A self-contained local web stack with Postgres, API, and web UI.
- A standalone scanner/CLI for CI and workstation scanning.

The OSS stack is intentionally single-tenant and self-hosted. It does not call any external Relix-Q service.

## Local web stack

```bash
cp .env.example .env   # optional
docker compose up --build
```

Open http://localhost:47000, sign up, create a project, and run a scan.

The compose stack starts:

| Service | Image/build | Host port | Notes |
| --- | --- | --- | --- |
| `postgres` | `postgres:15-alpine` | `47432` | Stores users, projects, scans, findings, and uploaded-source metadata. |
| `api` | `apps/api/Dockerfile` | `47080` | ASP.NET API plus the Go scanner engine. |
| `web` | `apps/web/Dockerfile` | `47000` | Next.js web UI. |

Persistent Docker volumes:

| Volume | Purpose |
| --- | --- |
| `pgdata` | Postgres data. |
| `uploads` | Uploaded `.zip` source archives for rescans. |

## Scanning local source

For Local path projects, put source under `./scan-targets` or change `LOCAL_SCAN_PATH` in `.env`.

```bash
mkdir scan-targets
# copy or symlink source under scan-targets/
docker compose up --build
```

The API mounts that folder read-only at `/scan`, and Local path project values are resolved as subpaths under that root.

## Standalone scanner

For CI or one-off evaluation, use a release archive or the published scanner image:

```bash
relixq scan /path/to/repo --format sarif > relixq.sarif
docker run --rm -v "$PWD:/src" ghcr.io/xops-labs/relixq:latest scan /src
```

The GitHub Action in `github-action/` wraps the same scanner flow and is shown in `docs/ci-examples/github.yml`.

## Long-running self-hosted use

For anything beyond a local demo:

- Change `POSTGRES_PASSWORD` and keep `.env` out of source control.
- Put the web/API behind TLS if exposed outside localhost.
- Back up the `pgdata` and `uploads` volumes if the scan history matters.
- Keep uploaded archives and local scan mounts limited to source you are allowed to process.
- Review `SECURITY.md` before exposing the API to a shared network.
- Treat the compose stack as a simple self-hosted OSS deployment.

## Upgrades

1. Read `CHANGELOG.md` and `docs/RELEASE.md`.
2. Pull the new source or update the release artifact.
3. Rebuild the stack:

```bash
docker compose down
docker compose up --build
```

The API uses `EnsureCreated` plus small additive bootstrap SQL for the demo schema. There is no formal production migration system in this OSS stack yet.
