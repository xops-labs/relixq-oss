# Configuration

Relix-Q OSS is designed to run with no local configuration. `docker compose up --build` works with the defaults in `docker-compose.yml`; copy `.env.example` to `.env` only when you want to change ports, database credentials, or the local scan mount.

## Docker Compose variables

These variables are read by `docker-compose.yml`.

| Variable | Default | Used by | Purpose |
| --- | --- | --- | --- |
| `WEB_PORT` | `47000` | web, api CORS origin | Host port for the Next.js web UI. |
| `API_PORT` | `47080` | api | Host port for the ASP.NET API. |
| `POSTGRES_PORT` | `47432` | postgres | Host port for Postgres. |
| `POSTGRES_USER` | `relixq` | postgres, api | Postgres user. |
| `POSTGRES_PASSWORD` | `relixq` | postgres, api | Postgres password. Change this for shared or long-running environments. |
| `POSTGRES_DB` | `relixq` | postgres, api | Postgres database name. |
| `LOCAL_SCAN_PATH` | `./scan-targets` | api | Host folder mounted read-only at `/scan` for Local path projects. |

Example:

```bash
cp .env.example .env
WEB_PORT=48000 API_PORT=48080 docker compose up --build
```

## API settings

The API uses normal ASP.NET configuration binding, so environment variables with double underscores override nested settings.

| Setting | Default in source | Docker image/compose value | Purpose |
| --- | --- | --- | --- |
| `ConnectionStrings__Postgres` | localhost Postgres connection string | `Host=postgres;Port=5432;...` | API database connection. |
| `Web__Origin` | `http://localhost:47000` | `http://localhost:${WEB_PORT:-47000}` | Allowed browser origin for the web app. |
| `Scan__ScannerBin` | `relixq-scan-code` | `/app/bin/relixq-scan-code` | Scanner engine executable used by API scans. |
| `Scan__RulesDir` | `rules` | `/app/rules` | OSS rule directory passed to the scanner. |
| `Scan__FixturesDir` | `fixtures` | `/app/fixtures` | Bundled sample scan targets. |
| `Scan__LocalRoot` | `/scan` | `/scan` | In-container root for Local path scans. |
| `Scan__GitBin` | `git` | `git` | Git executable for repository scans. |
| `Scan__TimeoutSeconds` | `300` | `300` | Per-process timeout for clone and scan operations. |

The API bootstraps its demo schema with `EnsureCreated`; this repo does not ship a production migration workflow.

## Web settings

| Variable | Default | Purpose |
| --- | --- | --- |
| `RELIXQ_API_BASE_URL` | `http://localhost:5099` in source, `http://api:8080` in compose | Server-side API base URL used by Next.js actions and route handlers. |
| `NEXT_PUBLIC_APP_NAME` | `Relix-Q OSS` | Display name in the web app. |

For the compose stack, keep `RELIXQ_API_BASE_URL` pointed at the internal service URL (`http://api:8080`), not the host-mapped port.

## CLI and scanner settings

The standalone `relixq` CLI and scanner engine also honor environment variables for advanced local builds:

| Variable | Purpose |
| --- | --- |
| `RELIXQ_SCANNER_BIN` | Explicit scanner executable used by `relixq scan`. |
| `RELIXQ_RULE_DIR` | Explicit OSS rule directory used by `relixq scan`. |
| `RELIXQ_RULE_PACK` | Optional external migration-enrichment overlay for hosts that have it. Not required for OSS detection. |
| `RELIXQ_API_URL` | API URL used by CLI commands that talk to a Relix-Q server. |
| `RELIXQ_PROJECT` | Default project name/id for server-oriented CLI flows. |
| `RELIXQ_ROSLYN_BIN` | Optional C# AST helper when building/running outside the Docker image. |
| `RELIXQ_PYTHON_BIN` | Optional Python interpreter for builds that wire in the Python AST runner. |
| `RELIXQ_PYTHON_SCRIPT` | Optional Python AST helper script path. |

Released archives are built so the CLI can find the scanner and bundled rules next to itself without these variables.

## Secrets and local files

- Do not commit `.env`, access tokens, private repositories, uploaded source archives, or scan outputs.
- Private git access tokens are used only for clone operations, but they should still be short-lived and scoped to read-only repository access.
- Local path scans mount `LOCAL_SCAN_PATH` read-only into the API container.
- Uploaded `.zip` archives are stored in the Docker `uploads` volume so projects can be rescanned after a restart.
