# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-06-19

### Added
- Local DNS management page: add, edit, and delete custom DNS records (A, AAAA,
  CNAME, MX, TXT, SRV, PTR) backed by AdGuard `$dnsrewrite` rules, managed as one
  logical record set across both HA servers, with a type-aware modal editor.
- `/healthz` liveness endpoint and a container `HEALTHCHECK` for the production
  image.
- Per-IP login rate limiting with temporary lockout after repeated failures.

### Changed
- Fetch each server's status, stats, and filtering concurrently so a slow or
  unreachable instance no longer serializes the dashboard load.
- Allow browsers to cache static assets with revalidation instead of `no-store`.
- Add unit tests for DNS/whitelist rule parsing and session validation.

### Fixed
- Require panel authentication by default and stop shipping a default password;
  a random one is generated on first run and logged once.
- Invalidate existing sessions when the panel password changes, and mark the
  session cookie `Secure` when served over HTTPS.
- Refuse to synchronize an empty source rule set that would wipe the destination.
- Bound AdGuard response bodies before decoding to prevent memory exhaustion.
- Reject non-`http(s)` AdGuard server URLs.
- Run the production container as a non-root user.
- Pin the Go toolchain to 1.26.4 to clear known standard-library vulnerabilities.
- Set `ReadTimeout`, `WriteTimeout`, and `IdleTimeout` on the HTTP server.
- Log the underlying cause when an interactive action fails.
- Relabel the uptime data download so it is not mistaken for a full backup.

## [1.0.0] - 2026-06-19

### Added
- Initial release: a Go + HTMX dashboard for managing one or two AdGuard Home
  instances (Master/Backup HA or single-server), shipped as a single static
  binary with embedded templates, assets, and locale bundles.
- Live dashboard with protection status, query/block stats, a CSS traffic chart,
  and 30s HTMX auto-refresh.
- Protection control (enable, disable, timed pause with live countdown),
  whitelist editor, and Master/Backup rule sync (manual and scheduled).
- Uptime history collected by a background worker, plus a runtime configuration
  management page that applies changes live.
- JSON-based Turkish and English localization and optional signed-cookie panel
  authentication.
- Docker development stack with live reload and two seeded AdGuard Home
  instances, and a production stack, both persisting under `docker-data`.
