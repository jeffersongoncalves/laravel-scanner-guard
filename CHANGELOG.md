# Changelog

All notable changes to this project will be documented in this file.

## 2.7.1 - 2026-11-27

- `scanner-guard:import --as=ban`: counts a ban applied without an audit row (cache and http drivers) as new, checking the ignore list itself. (#61)
- `scanner-guard:import --as=block|ignore`: refreshes the blocklist cache even when the import fails midway.
- `scanner-guard:ban-report`: marks a range as blocked only when one entry covers all of it.
- `scanner-guard:whois`: a timed-out lookup becomes an error row instead of aborting the report.

## 2.7.0 - 2026-11-27

- `scanner-guard:import {file} --as=ban|block|ignore`: load a list of IPs or CIDRs as bans (reason `manual`), blocklist or ignore entries. (#60)
- `scanner-guard:ban-report`: group the stored ban IPs (`store_details`) by /24 and /16 to find bot networks, flagging the ranges already blocked.
- `scanner-guard:whois {network}`: list the banned IPs of a range with owner, network and country.
- `ScannerGuard::canonicalIp()` and `ScannerGuardBan::REASON_MANUAL`.

## 2.6.0 - 2026-11-27

- Agent events: `POST {http.server.path}/events` stores report-rule events (e.g. every accepted SSH login) in `scanner_guard_agent_events` with `fields`, `ignored` and `first_seen`; IP and log line only with `store_details`, encrypted. Fires `AgentEventRecorded`. Answers 404 until the migration runs. (#59)
- Hourly attack counts: the heartbeat's `matches` is summed per source, rule and hour into `scanner_guard_agent_metrics`.
- `scanner-guard:aggregate-and-prune` prunes both tables past `retention_days`.

Both migrations are optional. Pairs with scanner-guard-agent 2.6.0.

## 2.5.1 - 2026-11-26

### Fixed

- A cache flush no longer drops the older bans from the denylist pull and the sinks. With `store_details` on, a ban whose cached raw IP is gone is served from the IP its row stored (encrypted), checked against its hash and cached back until the ban expires. Bans reported by scanner-guard-agent never hit the central app again, so before this they stayed out for good (#58).

No migration. Without stored details nothing changes.

## 2.5.0 - 2026-11-26

### Added

- Agent rule settings, set once for every server: the new `create_scanner_guard_agent_rules_table` migration and `ScannerGuardAgentRule` model hold a threshold, window (`10m`) and ban steps (`1d, 7d, 30d`) per scanner-guard-agent rule name. The denylist response serves them in seconds under `agent_rules`, signed with the rest (#57).

### Upgrading

Re-publish the migrations and run `php artisan migrate` on the central app. Until then the key is absent and agents keep their own settings. Agents 2.5.0+ apply the rows; older agents ignore them.

## 2.4.0 - 2026-11-26

### What's new

#### Log lines of agent bans

Bans forwarded by [scanner-guard-agent](https://github.com/jeffersongoncalves/scanner-guard-agent) (2.3.0+) carry `evidence`: the log lines that tripped the agent's rule, with the banned IP replaced by `<ip>`. With `store_details` on, the central app stores them encrypted in the new `evidence` column, so you can see what an IP actually tried:

```php
$ban->evidence; // ['<ip> - [25/Nov/2026:22:19:53 -0300] "GET /.env.staging HTTP/2.0" 403 rule=dotfile ...']






```
- Up to 20 lines of 1024 characters per ban; anything else is refused with `422`.
- Hidden from `toArray()` / `toJson()`, like `ip`. The lines come from the attacker (query strings, User-Agents): escape them when displaying them.
- Not stored with details off, nor for bans without lines (older agents, local bans).

### Upgrading

New migration, `add_evidence_to_scanner_guard_bans_table`: re-publish the migrations and run `php artisan migrate` on the central app, then restart its workers. Agents can be upgraded before or after it: until the column exists, the ban is stored as before, without its lines.

**Full Changelog**: https://github.com/jeffersongoncalves/laravel-scanner-guard/compare/2.3.0...2.4.0

## 2.3.0 - 2026-11-25

### What's new

#### Signed denylist response

The central app signs its answer to the denylist `GET` with the source's secret, bound to the request it answers, so nobody on the way (a CDN, a load balancer) can change the list. `scanner-guard:pull-denylist` verifies it: a bad signature fails the pull and keeps the last list. `SCANNER_GUARD_HTTP_REQUIRE_SIGNED_RESPONSE=true` also refuses an unsigned response (off by default, for older central apps).

#### IP ignore list

`ip_ignore`, or runtime rows with `ScannerGuardBlocklistEntry::TYPE_IGNORE` (no new migration), lists IPs and CIDR ranges never blocked or banned:

- they skip every check of the middleware, and a ban of them (local or forwarded) is never stored;
- a ban stored before the IP was listed stops blocking it, and leaves the denylist and the sinks;
- satellites get the list with each pull.

Invalid entries and ranges wider than /8 (IPv4) or /16 (IPv6) have no effect. An `ip_blocklist` range that contains an ignored IP still reaches the sinks whole.

### Upgrading

No migration. Update the central app first, then the satellites, and only then turn on `require_signed_response` on each satellite.

A config published earlier has no line reading the new env. Add it to its `http` block, or the setting is silently ignored:

```php
'require_signed_response' => env('SCANNER_GUARD_HTTP_REQUIRE_SIGNED_RESPONSE', false),







```
**Full Changelog**: https://github.com/jeffersongoncalves/laravel-scanner-guard/compare/2.2.1...2.3.0

## 2.2.1 - 2026-11-24

### Security

- Ban reasons handed to denylist sinks are limited to `[A-Za-z0-9_.-]`; anything else becomes `_`. A forwarded or pulled reason is free text that sinks write into config comments (e.g. the nginx deny file), where a newline let the holder of a valid forwarding secret, or the central app, add its own directives. Built-in reasons are unchanged, and stored bans are covered too. (#51)

### Docs

- The README, config comments and Boost docs list the new sinks: [Apache](https://github.com/jeffersongoncalves/laravel-scanner-guard-apache), [Caddy](https://github.com/jeffersongoncalves/laravel-scanner-guard-caddy) and [FrankenPHP](https://github.com/jeffersongoncalves/laravel-scanner-guard-frankenphp). (#52)

No config change or migration needed.

**Full Changelog**: https://github.com/jeffersongoncalves/laravel-scanner-guard/compare/2.2.0...2.2.1

## 2.2.0 - 2026-11-24

### What's new

#### Ban details for incident investigation (opt-in)

`SCANNER_GUARD_STORE_DETAILS=true` also keeps, in each ban row, the IP (`$ban->ip`, encrypted with the app key, hidden from `toArray()` / `toJson()`) and the request path without its query string (`$ban->path`). It covers local bans and bans forwarded to a central app, so an attacker can be traced across servers and after the ban expired. Off by default: the table keeps holding only a salted hash of the IP.

With that env on, `purge_expired_after_days` defaults to `null`, so expired rows are kept until `retention_days`. An explicit `SCANNER_GUARD_PURGE_EXPIRED_AFTER_DAYS` still wins.

#### One row per source

A central app used to merge every ban of one IP forwarded within 60 seconds into a single row. It now merges per IP **and source**: replicas sharing a source still make one row, every other server gets its own.

#### Fixes

- A shorter ban no longer cuts a longer cached one short: bans of one IP are cached and stored under a per-IP lock.
- The 60-second guard never outlives a forwarded ban.
- A path with invalid UTF-8 no longer makes a forwarded ban fail to encode.
- README: the IP hash is pseudonymous, not irreversible (whoever holds the salt can brute-force IPv4).

### Behavior change

With or without `store_details`, a central app now stores, and counts in the daily stats, one ban per source when several servers are hit at once.

### Upgrading

Only needed to use `store_details`. Publish and run the new migration on the central app **before** turning it on:

```bash
php artisan vendor:publish --tag="scanner-guard-migrations"
php artisan migrate








```
A config published earlier still defaults `purge_expired_after_days` to `0`: update that line, or set `SCANNER_GUARD_PURGE_EXPIRED_AFTER_DAYS`, to keep the history. After rotating `APP_KEY`, keep the old key in `APP_PREVIOUS_KEYS` to read stored IPs.

Satellites need no config change or migration.

**Full Changelog**: https://github.com/jeffersongoncalves/laravel-scanner-guard/compare/2.1.0...2.2.0

## 2.1.0 - 2026-11-22

### What's new

#### Agent heartbeats

Central apps now record heartbeats from [scanner-guard-agent](https://github.com/jeffersongoncalves/scanner-guard-agent), a static Go binary that watches sshd, nginx or any log on Linux servers, bans offenders in nftables and forwards its bans here.

- New route `POST {http.server.path}/heartbeat` (only with `http.server.enabled`), checked like a forwarded ban: per-source secret, timestamp tolerance, replay nonce, signed JSON body only.
- New `ScannerGuardAgent` model, one row per source: `version`, `rules`, `active_bans`, `started_at`, `last_seen_at`, with `online()` / `offline()` scopes and `isOnline()`.
- The `source` column is case-sensitive on MySQL/MariaDB, so another casing of a source can't overwrite its row.

#### Upgrading

Publish and run the new migration on the central app:

```bash
php artisan vendor:publish --tag="scanner-guard-migrations"
php artisan migrate








```
Satellites need no change.

**Full Changelog**: https://github.com/jeffersongoncalves/laravel-scanner-guard/compare/2.0.3...2.1.0

## 2.0.3 - 2026-11-19

### Fixed

- http driver: satellites now forward their bans to the central app. The POST ran in a `defer()` callback, which Laravel skips when the response is >= 400, and the banning request always answers 404 (or `response_status`). It is now marked `always()`. (#45)

## 2.0.2 - 2026-11-19

### Fixed

- Raw IP recovery (2.0.1) re-caches with an atomic add, so a ban stored meanwhile (e.g. an escalated one with a longer expiry) keeps its own entry.
- A database error during that recovery is reported instead of turning the banned response into a 500 (#44).

## 2.0.1 - 2026-11-19

### Fixed

- A banned IP whose raw IP was lost from the cache (a `cache:clear`, an eviction) is now cached again when it comes back, and the denylist sinks are re-synced, so the ban reaches nginx, Cloudflare or Traefik again instead of staying app-only until it expires. `database` driver only, at most one lookup a minute per IP (#43).

## 2.0.0 - 2026-11-19

### Denylist sinks

The nginx export moved out of the core. scanner-guard now pushes the denylist to pluggable **sinks**, each its own package:

- [laravel-scanner-guard-nginx](https://github.com/jeffersongoncalves/laravel-scanner-guard-nginx): the old `sync_to_nginx` export (same file, lines and env vars)
- [laravel-scanner-guard-cloudflare](https://github.com/jeffersongoncalves/laravel-scanner-guard-cloudflare): keeps a Cloudflare Custom IP List in sync for a WAF rule
- [laravel-scanner-guard-traefik](https://github.com/jeffersongoncalves/laravel-scanner-guard-traefik): serves the list to Traefik's HTTP provider

#### Added

- `Contracts\DenylistSink` and `ScannerGuard::denylistEntries()`
- `scanner-guard:sync-denylist`: runs every configured sink under one lock; a failing sink is logged and the others still run
- `sinks` and `sync_on_ban` config keys

#### Breaking

- Removed `sync_to_nginx`, the `nginx` config block, `scanner-guard:export-denylist`, `ExportDenylistCommand` and `ExportDenylist` (now `SyncDenylistCommand` / `SyncDenylist`)

See [UPGRADE.md](https://github.com/jeffersongoncalves/laravel-scanner-guard/blob/main/UPGRADE.md) (#42).

## 1.8.0 - 2026-11-19

### Added

- **Record which satellite forwarded each ban** (#37, #38). With the `http` driver, satellites send `source` (`SCANNER_GUARD_HTTP_SOURCE`, default `APP_NAME`) in the signed payload, and the central app stores it in the new nullable, indexed `source` column. Bans made by the central app itself keep `source = null`.
  
- **Per-source secrets** on the central app: `scanner-guard.http.secrets` (`[shop => ..., blog => ...]`). A listed source is only accepted when signed with its own secret, so one satellite cannot forward bans under another name. Unlisted sources fall back to `http.secret`; set it to `null` to accept listed sources only.
  
- **Distribute the central denylist to satellites** (#39, #40). The central app now also answers a signed `GET` on `http.server.path` with its active bans, `ip_blocklist` and user-agent patterns (config + database). With `SCANNER_GUARD_HTTP_PULL=true`, satellites run `scanner-guard:pull-denylist` every minute:
  
  - each pulled ban is cached until it expires, so the middleware blocks it;
  - the static lists are merged into the satellite lists;
  - bans lifted on the central app (unban) are lifted on the satellite;
  - with `sync_to_nginx`, the satellite rewrites its own nginx denylist after each pull.
  
  A failed pull is logged, exits non-zero and keeps the last list.
  

### Changed

- `scanner-guard:export-denylist` now also runs on the `http` driver, exporting the pulled bans.

### Fixed

- Forwarded bans are validated from the signed JSON body only. Before, the unsigned query string could fill in a field the body left out (e.g. `?source=`).

### Upgrade

1. On the central app, publish and run the new `add_source_to_scanner_guard_bans_table` migration **before** upgrading satellites. Without the column, the central app cannot store bans from upgraded satellites (the satellite logs the error and keeps its local ban).
2. Use an `https` URL: the denylist response carries raw IPs and is not signed itself.

## 1.7.2 - 2026-11-04

### Fixed

- **One ban per burst of concurrent requests from one IP** (#34, #35). Concurrent requests all passed `isBanned()` before the first ban was cached, so each one stored its own row and the escalation offense climbed with every row (1 → 4 in one second). `ban()` and `recordForwardedBan()` now claim a short per-IP guard with an atomic cache `add()`. Duplicates return `null` and store nothing. The guard lasts min(60s, shortest configured ban), is released when a ban throws before it is stored, and `unban()` clears it.
- On the central app (http driver), several satellites forwarding the same burst now store a single row.

### Changed

- `recordForwardedBan()` now returns `?ScannerGuardBan`.
- Multi-server setups should point `scanner-guard.store` at a cache shared by all servers (e.g. redis) so the burst guard and hit counters coordinate across them.

### Note

Duplicate rows already stored before this release are not collapsed. They age out with `escalation_lookback_days`.

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
