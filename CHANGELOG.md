# Changelog

All notable changes to this project will be documented in this file.

## 1.7.1 - 2026-11-02

### Fixed

- `scanner-guard:export-denylist` writes one `deny` line per IP/CIDR. An escalated IP with several active ban rows now gets a single line carrying its latest expiry, and an IP that is also in the static blocklist only gets its `# static` line (#32, #33).

## 1.7.0 - 2026-11-02


---

### source: claude-code

tags: [scratchpad]
project: laravel-scanner-guard
title: release-1.7.0
created: 2026-11-02T19:29:54+00:00
updated: 2026-11-02T19:29:54+00:00

### Added

- **Database-backed IP / User-Agent blocklist** (#30, #31). With the `database` driver, entries in the new `scanner_guard_blocklist` table (`ScannerGuardBlocklistEntry`, types `ip` / `user_agent`) are added on top of `ip_blocklist` and `user_agent_blocklist.patterns`, so they change without a config edit or redeploy. DB IPs also reach the nginx export as `# static` lines.
  
  - Cached under a versioned key in the scanner-guard store: two cache reads per check, no query. Read on every call, so queue workers and Octane pick up a change without re-booting.
  - Saving or deleting an entry refreshes the list and, with `sync_to_nginx`, queues the export, only after the transaction commits. A mass `query()->delete()` / `update()` fires no model events: call `ScannerGuard::blocklistChanged()` after one.
  - If the table is missing, the config lists still apply and the error is reported.
  
- **`ScannerGuard::unban(string $ipHash): int`**. Deletes the active ban rows for that hash, forgets the cached ban and raw IP (so the IP passes at once, not after the cached ban expires) and, with `sync_to_nginx`, queues the export. Returns the number of rows deleted.
  
- `ScannerGuard::userAgentPatterns()` and `ScannerGuard::blocklistChanged()`.
  

### Changed

- `nginx.export_on_ban` now gates only exports on new bans. `unban()` and blocklist changes always queue an export when `sync_to_nginx` is on.

### Upgrading

Publish and run the new migration:

```bash
php artisan vendor:publish --tag="scanner-guard-migrations"
php artisan migrate


```
It is a no-op when `scanner_guard_blocklist` already exists, so apps that ran the one from `filament-scanner-guard` keep their rows. Rolling it back keeps the table for the same reason. Nothing else is required; without the migration the package keeps working from the config lists.

## 1.6.0 - 2026-11-02

### Added

- **nginx denylist follows bans in near real time** (#24, #27). With `sync_to_nginx` on, every new ban (local or forwarded) queues a unique `ExportDenylist` job, so the file follows the ban table within seconds. New config `scanner-guard.nginx`:
  
  - `path` (env `SCANNER_GUARD_NGINX_PATH`): shared by the scheduled run and the job; `--path` still overrides it.
  - `export_on_ban` (env `SCANNER_GUARD_NGINX_EXPORT_ON_BAN`, default `true`).
  - `reload_command` (env `SCANNER_GUARD_NGINX_RELOAD_COMMAND`, e.g. `sudo nginx -s reload`): runs only when the file content changed. A failure or timeout is logged, never thrown. See the README for the sudoers line.
  
- **Permanent IP / CIDR blocklist** (#25, #28). `scanner-guard.ip_blocklist` (IPv4 + IPv6) is rejected before any counting, with no ban row and no expiry. The export writes these entries as `deny ...; # static` lines and skips invalid ones, so a typo can't break `nginx -t`.
  
- **User-Agent blocklist** (#26, #29). `scanner-guard.user_agent_blocklist` adds `block_empty`, `patterns` (fnmatch, case-insensitive) and `action` (`ban` / `reject`). It adds a new ban reason, `user_agent`, which is also in the default `escalation_reasons`.
  

### Changed

- With `sync_to_nginx` on, `scanner-guard:export-denylist` is now scheduled `everyMinute()->withoutOverlapping()` instead of `daily()`, so expired bans leave nginx within about a minute. This stays cheap because the file is only rewritten when its content changes.
- The denylist is written atomically (temp file + `rename()`). All exports run under one cache lock, so an older snapshot never overwrites a newer one.

### Upgrading

No migration needed. If you published the config, copy over the new `nginx`, `ip_blocklist` and `user_agent_blocklist` keys. To escalate UA bans, also add `user_agent` to `escalation_reasons`. All new features are opt-in; defaults keep the 1.5.x behaviour, except that the export now runs every minute when `sync_to_nginx` is on.

## 1.5.1 - 2026-10-28

### Fixed

- `isBanned()` now caches a database miss as `false` for `negative_cache_ttl` seconds (default `60`, env `SCANNER_GUARD_NEGATIVE_CACHE_TTL`, `0` disables), so non-banned traffic no longer costs one query on `scanner_guard_bans` per request. `ban()` overwrites the entry, so new bans apply immediately. (#21, #22)

## 1.5.0 - 2026-10-28

### Added

- Opt-in escalating ban duration for repeat offenders (#18, #19). Set `scanner-guard.escalation` to a ladder of seconds per offense, e.g. `[86400, 604800, 1209600, 2592000, 7776000]` (1d → 7d → 14d → 30d → 90d; the last step repeats). Configure it with `escalation_lookback_days` (default 365) and `escalation_reasons` (default `scanner_path`, `not_found_flood`).
- New nullable `offense` column on `scanner_guard_bans`. It is also included in the ban log and in the `http` driver payload.
- `cache`/`http` drivers track offenses in a cache counter (best effort, resets on a cache flush).

### Changed

- While escalation is on, `scanner-guard:aggregate-and-prune` keeps each IP's latest escalated ban inside the lookback and prunes only past `max(retention_days, escalation_lookback_days)`.

### Upgrading

Re-publish the migrations and migrate to add the `offense` column. You only need it to enable escalation with the `database` driver:

```bash
php artisan vendor:publish --tag="scanner-guard-migrations"
php artisan migrate





```
## 1.4.0 - 2026-10-28

### Added

- Opt-in 404-flood ban (#16, #17): `not_found_threshold` / `not_found_window` (env `SCANNER_GUARD_NOT_FOUND_THRESHOLD`, `SCANNER_GUARD_NOT_FOUND_WINDOW`, default off / 60s). An IP that gets that many 404 responses within the window is banned with the new reason `ScannerGuardBan::REASON_NOT_FOUND_FLOOD` (`not_found_flood`), from the next request on. scanner-guard's own responses are never counted.

### Fixed

- Hit counters are initialised with the cache's atomic `add()` instead of `has()` + `put()`, so concurrent requests can no longer reset an increment.

### Docs

- README "404 flood" section, including why `Route::fallback()` (GET/HEAD only) misses other methods and an all-method catch-all route to count unmatched URLs.

## 1.3.0 - 2026-10-01

### What's New

The package no longer requires a SQL database. New `scanner-guard.driver` config (env `SCANNER_GUARD_DRIVER`):

- **`database`** (default): unchanged behavior, audit rows + daily stats in SQL.
- **`cache`**: bans live only in the cache store for `ban_duration`. No audit trail, stats or nginx export, no migrations needed.
- **`http`**: bans stay in the local cache and are forwarded (after the response, short timeout, failures only logged) to a central app over an HMAC-signed request: `X-Signature: hash_hmac('sha256', X-Timestamp.body, secret)`.

Central app: set `SCANNER_GUARD_HTTP_SERVER_ENABLED=true` to register `POST scanner-guard/bans`. It rejects bad signatures and stale timestamps (403) and replays (409), then records the ban like a local one (its own salted `ip_hash`, daily stats, raw IP in cache only), so its nginx export covers every satellite.

`scanner-guard:aggregate-and-prune` and `scanner-guard:export-denylist` are not scheduled, and skip with a notice, unless the driver is `database`.

### Upgrading

No action needed for the default `database` driver. `ScannerGuard::ban()` now returns `?ScannerGuardBan` (`null` for `cache`/`http`). If you published the config, add the new `driver` and `http` keys (see README > Running without a database).

Closes #12

## 1.2.0 - 2026-09-27

### What's New

- Daily ban stats are now recorded at ban time, keyed by the day the ban was **created** (`banned_at`) instead of the day it expired. The history survives purges, unbans and retention pruning.
- `scanner-guard:aggregate-and-prune` reconciles every day from the oldest remaining ban up to yesterday (`max(existing, recomputed)`, never lowering a counter), so days skipped by the scheduler are backfilled.
- Expired bans are purged automatically once their day is recorded — new `scanner-guard.purge_expired_after_days` config (default `0` = next run, `null` disables, env `SCANNER_GUARD_PURGE_EXPIRED_AFTER_DAYS`).
- New `ScannerGuard::dailyStats(int $days = 14)` reader: one zero-filled entry per day, today live.
- New `--rebuild` option to overwrite stats from the remaining ban rows.

### Upgrading

Stats written by earlier releases are keyed by expiry day. Run once right after upgrading, before the scheduled run purges expired bans:

```bash
php artisan scanner-guard:aggregate-and-prune --rebuild








```
Closes #8

## 1.1.0 - 2026-09-14

### What's New

- `scanner-guard:aggregate-and-prune` command: folds each day's expired bans into a new `scanner_guard_ban_daily_stats` table (bans_count, hits_total, reason_stats, top_matched_values), then prunes raw ban rows past `scanner-guard.retention_days` (default 90). Still-active bans are never touched.
- Self-schedules daily via new `scanner-guard.auto_prune` config (default true, env `SCANNER_GUARD_AUTO_PRUNE`).

Closes #2

## 1.0.0 - 2026-09-13

Initial release.

- Middleware `BlockScannerRequests` — opt-in, detects known vulnerability-scanner paths (WordPress probes, .git/.env leaks, admin-tooling scans, framework probes) and repeat offenders get banned after a configurable threshold.
- Optional ASN-level hard block via `jeffersongoncalves/laravel-visitor-fingerprint`'s resolved GeoIP data.
- `scanner_guard_bans` table for permanent audit — stores only a salted IP hash, never a raw IP.
- `scanner-guard:export-denylist` command to generate an nginx `deny <ip>;` denylist file for edge-level blocking.
- Deliberately responds 404 (not 403) by default so a banned scanner can't distinguish "banned" from "route doesn't exist".

## [Unreleased]
