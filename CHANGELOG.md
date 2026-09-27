# Changelog

All notable changes to this project will be documented in this file.

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
