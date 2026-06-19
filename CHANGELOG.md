# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
