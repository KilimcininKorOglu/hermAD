# hermAD

A self-hosted dashboard for managing AdGuard Home instances. It supports High
Availability setups (Master/Backup) and single-server mode, and is written in Go
with an HTMX-driven frontend. The entire application ships as a single static
binary with embedded templates, assets, and locale bundles.

## Features

- Live dashboard: protection status, latency, query and block counts, and a
  CSS-rendered traffic chart per server (auto-refreshes every 30s).
- Protection control: enable, disable, or timed-pause (with a live countdown).
- Whitelist editor: one domain per line, persisted to AdGuard Home user rules.
  Non-allow rules on the server are preserved untouched.
- Bidirectional sync (HA mode): Master to Backup and Backup to Master, manual or
  scheduled (auto-sync).
- Uptime history: per-server up/down bars, collected by a background worker.
- Configuration management page: edit servers, authentication, language, uptime,
  and auto-sync at runtime — changes apply live, no restart required.
- JSON-based localization: Turkish and English, switchable from the UI.
- Optional panel authentication with signed-cookie sessions.
- Single-server mode: set `backup_server` to false to hide all HA and sync UI.

## Architecture

Everything is one Go binary. HTML is server-rendered with `html/template`;
interactivity uses HTMX (vendored, no CDN). Runtime state lives in a data
directory, never in the binary:

- `internal/config` — runtime-editable configuration with atomic, persisted swaps
- `internal/adguard` — minimal AdGuard Home control API client
- `internal/store` — uptime history and last-sync persistence
- `internal/i18n` — JSON locale bundles
- `internal/server` — routing, middleware, handlers, and the background ticker
- `web/` — embedded templates and static assets; `locales/` — embedded bundles

## Configuration

Configuration is stored as `config.json` in the data directory and is created
with defaults on first run. Edit it through the admin page (recommended) or
directly. Environment variables:

| Variable          | Default         | Purpose                        |
|-------------------|-----------------|--------------------------------|
| `HERMAD_DATA_DIR` | `./docker-data` | Directory for config and state |
| `HERMAD_LISTEN`   | `:8080`         | HTTP listen address            |

The data directory holds `config.json` (contains credentials), `data.json`
(uptime and last-sync), and `session.key` (session signing secret). It must be
writable and must not be committed to version control.

## Running with Docker

All persistent data is bind-mounted under `./docker-data` (no named volumes).

### Development

The development stack runs hermAD with live reload (air) plus two seeded AdGuard
Home instances, so HA features can be exercised locally:

```bash
docker compose -f hermad-dev.yml up --build
```

| Service        | URL                       | Notes                           |
|----------------|---------------------------|---------------------------------|
| hermAD         | http://localhost:8160/    | live reload on source changes   |
| AdGuard Master | http://localhost:8161/    | seeded, authentication disabled |
| AdGuard Backup | http://localhost:8162/    | seeded, authentication disabled |
| AdGuard DNS    | `127.0.0.1:8163` / `8164` | master / backup (TCP + UDP)     |

The AdGuard instances are seeded from `deploy/adguard/AdGuardHome.yaml` into
`docker-data/adguard-master` and `docker-data/adguard-backup`, and hermAD is
pre-pointed at them via `config.dev.json`. The seed is for development only.

### Production

```bash
docker compose -f hermad-prod.yml up --build -d
```

Publishes the UI on host port `8160` and persists to `./docker-data`.

## Running locally

Requires Go 1.26+.

```bash
go run .
# build (output goes to ./bin)
go build -o bin/hermad . && ./bin/hermad
```

The UI is served on `:8080`. The data directory is chosen by the user via
`HERMAD_DATA_DIR`; when unset it falls back to `./docker-data`.

## Automation

Uptime collection and optional auto-sync run inside the server process as a
background worker; no external cron is required. Configure the uptime check
interval and auto-sync direction/interval on the admin page.

## Versioning

The version lives in the `VERSION` file and is embedded into the binary at build
time (`go:embed`). Print it with `hermad --version`; it is also shown in the UI
footer and the startup log. Release a new version by editing `VERSION`.

## License

MIT License. See `LICENSE`.
