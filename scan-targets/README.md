# scan-targets

This folder is mounted **read-only** into the API container at `/scan` (see
[`docker-compose.yml`](../docker-compose.yml)). It's how the web app scans code that
lives on your machine.

## Use it

1. Copy or symlink a repo in here, e.g. `scan-targets/my-service/`.
2. In the web app, create a project with source **Local path** and enter the
   subfolder name (`my-service`). Leave it blank to scan everything under `scan-targets/`.
3. Run the scan.

Point the mount somewhere else by setting `LOCAL_SCAN_PATH` in `.env`
(e.g. `LOCAL_SCAN_PATH=/home/me/code`).

Paths are sandboxed to this directory — a project can't scan outside the mounted root.
