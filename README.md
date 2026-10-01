<div class="filament-hidden">

![Laravel Scanner Guard](https://raw.githubusercontent.com/jeffersongoncalves/laravel-scanner-guard/main/art/jeffersongoncalves-laravel-scanner-guard.png)

</div>

# Laravel Scanner Guard

[![Latest Version on Packagist](https://img.shields.io/packagist/v/jeffersongoncalves/laravel-scanner-guard.svg?style=flat-square)](https://packagist.org/packages/jeffersongoncalves/laravel-scanner-guard)
[![GitHub Tests Action Status](https://img.shields.io/github/actions/workflow/status/jeffersongoncalves/laravel-scanner-guard/tests.yml?branch=main&label=tests&style=flat-square)](https://github.com/jeffersongoncalves/laravel-scanner-guard/actions?query=workflow%3ATests+branch%3Amain)
[![GitHub Code Style Action Status](https://img.shields.io/github/actions/workflow/status/jeffersongoncalves/laravel-scanner-guard/pint.yml?branch=main&label=code%20style&style=flat-square)](https://github.com/jeffersongoncalves/laravel-scanner-guard/actions?query=workflow%3A%22Fix+PHP+code+styling%22+branch%3Amain)
[![Total Downloads](https://img.shields.io/packagist/dt/jeffersongoncalves/laravel-scanner-guard.svg?style=flat-square)](https://packagist.org/packages/jeffersongoncalves/laravel-scanner-guard)
[![License](https://img.shields.io/packagist/l/jeffersongoncalves/laravel-scanner-guard.svg?style=flat-square)](LICENSE.md)

Detects and bans vulnerability-scanner traffic on Laravel apps: WordPress/CMS/credential probes,
`.git`/config leaks, phpMyAdmin, and similar noise get counted per IP and banned after a threshold,
with optional hard-blocking by ASN via
[`jeffersongoncalves/laravel-visitor-fingerprint`](https://github.com/jeffersongoncalves/laravel-visitor-fingerprint).

## What this package does — and does not — handle

Vulnerability-scanner traffic against a Laravel app splits into two categories:

1. **Literal nonexistent `.php` files** (`/wp/index.php`, `/wordpress/index.php`, `/blog/index.php`,
   ...). These fail at the nginx/PHP-FPM layer — PHP-FPM logs "Unable to open primary script" —
   **before Laravel's front controller ever boots**. No PHP code, this package included, can see
   these requests at all. The fix lives in your nginx config, not in this package:

   ```nginx
   location ~ \.php$ {
       try_files $uri =404;
       # ... fastcgi_pass, etc.
   }
   ```

2. **Extension-less or otherwise-routable paths** that DO reach Laravel and get handled as an
   ordinary 404 by the router (`/wp-admin`, `/wp-login`, `/.git/config`, `/phpmyadmin`, `/wp-json`,
   ...). **This is what this package handles**: it counts repeat offenders per IP and bans them so
   later requests get a fast, cheap rejection instead of running through the full framework boot +
   routing + 404 view render.

If you're only seeing nginx-layer 404s (category 1) in your access logs, this package has nothing
to catch — fix `try_files` first.

## Installation

You can install the package via composer:

```bash
composer require jeffersongoncalves/laravel-scanner-guard
```

Publish the config file and run the migration:

```bash
php artisan vendor:publish --tag="scanner-guard-config"
php artisan migrate
```

The migrations are only needed for the default `database` driver — see
[Running without a database](#running-without-a-database).

## Usage

The package registers a `scanner-guard` route middleware alias but does **not** attach it to any
group automatically — opt in yourself, e.g. in `bootstrap/app.php`:

```php
use JeffersonGoncalves\ScannerGuard\Http\Middleware\BlockScannerRequests;

->withMiddleware(function (Middleware $middleware) {
    $middleware->appendToGroup('web', BlockScannerRequests::class);
})
```

or attach it to a specific route group instead:

```php
Route::middleware('scanner-guard')->group(function () {
    // ...
});
```

Once attached: a request matching one of `scanner-guard.scanner_paths` increments a per-IP hit
counter; after `ban_threshold` hits within `ban_window` seconds, the IP is banned for
`ban_duration` seconds. A banned IP gets an immediate `response_status` (404 by default —
deliberately indistinguishable from "route doesn't exist", so a scanner can't tell it got banned
and adjust its behavior).

### ASN blocklisting

Some traffic is worth blocking outright, no path match needed. A production analysis of this
package's own author's site found a single ASN (`AS16276`, OVH SAS) responsible for 70-80% of all
bot traffic with zero legitimate human visitors ever coming from it. Opt in per-app:

```php
// config/scanner-guard.php
'asn_blocklist' => ['AS16276'],
```

ASN resolution is delegated to `jeffersongoncalves/laravel-visitor-fingerprint`'s `GeoIpDriver` —
only the `ip_api` and `maxmind` drivers populate an ASN (the default `headers` driver doesn't), so
set `visitor-fingerprint.geoip.driver` accordingly for this to have any effect. When the blocklist
is empty (the default), the GeoIP driver is never even resolved — zero added latency/cost.

### Manual review

Every ban writes a row to `scanner_guard_bans` (`reason`, `matched_value`, `hit_count`,
`banned_at`, `expires_at`) — a permanent, privacy-safe audit trail:

```php
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardBan;

ScannerGuardBan::query()->active()->latest('banned_at')->get();
```

### Exporting to nginx

```bash
php artisan scanner-guard:export-denylist
# or a custom path:
php artisan scanner-guard:export-denylist --path=storage/app/scanner-guard/denylist.conf
```

Writes every currently-active ban as an nginx `deny <ip>;` line. `include` it from your server
block to close the loop with edge-level blocking:

```nginx
server {
    include storage/app/scanner-guard/denylist.conf;
    # ...
}
```

Nothing schedules this automatically unless you opt in via `scanner-guard.sync_to_nginx = true`
(env `SCANNER_GUARD_SYNC_TO_NGINX`), which self-schedules the export daily — left off by default
because writing files to disk on a schedule is far more deployment-specific (permissions, shared
vs. per-instance storage, whether nginx actually reloads the file) than a DB-only aggregate job.

### Aggregating and pruning

Every ban bumps a `scanner_guard_ban_daily_stats` row for the day it was **created** (`bans_count`,
`hits_total`, `reason_stats`, `top_matched_values` — aggregate columns only, no per-IP data). The
history is recorded at ban time, so it survives any later delete of the ban row: purge, unban or
retention prune.

`scanner-guard:aggregate-and-prune` then, in order:

1. reconciles every day from the oldest remaining ban up to yesterday against the ban rows still
   present — filling days the ban-time counter missed, never lowering a counter (`max(existing,
   recomputed)`, since deleted rows can't be recounted);
2. purges expired bans once their day is recorded, after `scanner-guard.purge_expired_after_days`
   (default `0` = next run; `null` disables);
3. deletes ban rows expired more than `scanner-guard.retention_days` (default 90) ago.

Still-active bans are never purged or pruned.

```bash
php artisan scanner-guard:aggregate-and-prune
# reconcile from a specific day:
php artisan scanner-guard:aggregate-and-prune --date=2026-01-15
# overwrite the stats from the remaining ban rows instead of keeping the higher value:
php artisan scanner-guard:aggregate-and-prune --rebuild
```

Read the history (one entry per day, zero-filled, today live):

```php
ScannerGuard::dailyStats(14); // Collection of ['date', 'bans_count', 'hits_total', 'reason_stats', 'top_matched_values']
```

> **Upgrading:** releases before this change keyed stats rows by the day a ban *expired* (one day
> late with the default `ban_duration`). Run `php artisan scanner-guard:aggregate-and-prune --rebuild`
> once right after upgrading — before the scheduled run purges the expired rows — to rebuild those
> days by `banned_at`.

Self-schedules daily unless you opt out via `scanner-guard.auto_prune = false` (env
`SCANNER_GUARD_AUTO_PRUNE`) — on by default, since (unlike `sync_to_nginx`) writing to the DB has no
deployment-specific footgun.

#### Privacy tradeoff

`scanner_guard_bans` only ever stores a salted hash of the IP (`ip_hash`, via
`jeffersongoncalves/laravel-visitor-fingerprint`'s `IpAnonymizer::hash()`) — never the raw address,
matching this ecosystem's other packages (`laravel-page-visits`, `laravel-short-url`). A hash can't
be reversed back into an IP, which is exactly the point — but an nginx `deny` line needs a real IP.

The chosen tradeoff: at ban time, the raw IP is cached separately (keyed by the same hash, TTL =
`ban_duration`) — **cache only, never the permanent table**. `scanner-guard:export-denylist` reads
active bans from the database, then looks up each one's raw IP in that cache entry. If the cache
entry has expired or been evicted (a `cache:clear`, an "array" driver that doesn't survive between
requests, LRU eviction under memory pressure, ...), that ban is silently skipped from the nginx
export — the command logs how many were skipped, but does not fail.

This means: the **database never contains a reversible IP**, and the **app-layer ban still applies
correctly regardless** (the fast-path/DB-fallback ban check in `isBanned()` only ever needs the
hash). The nginx denylist is best-effort and may lag or miss entries after a cache flush. If you
rely heavily on the nginx export, prefer a durable cache store (`redis`, `file`) over `array` via
`scanner-guard.store`.

### Running without a database

Hit counting and the ban fast-path always run on the cache store; only the audit trail, daily
stats, nginx export and the `isBanned()` DB fallback need SQL. Pick where bans go with
`scanner-guard.driver` (env `SCANNER_GUARD_DRIVER`):

| Driver | Bans stored in | Audit trail / stats / nginx export | Needs migrations |
|---|---|---|---|
| `database` (default) | cache + `scanner_guard_bans` | yes | yes |
| `http` | cache, forwarded to a central app | on the central app | no |
| `cache` | cache only, TTL = `ban_duration` | no | no |

With `http` or `cache`, a ban doesn't survive a cache flush, `ScannerGuard::ban()` returns `null`,
and `aggregate-and-prune` / `export-denylist` are neither scheduled nor run (they print a skip
notice).

#### `http`: one central app for many satellites

On each satellite (no database):

```dotenv
SCANNER_GUARD_DRIVER=http
SCANNER_GUARD_HTTP_URL=https://central.example.com/scanner-guard/bans
SCANNER_GUARD_HTTP_SECRET=a-long-random-shared-secret
```

On the central app (`database` driver, migrations run):

```dotenv
SCANNER_GUARD_HTTP_SERVER_ENABLED=true
SCANNER_GUARD_HTTP_SECRET=a-long-random-shared-secret
# optional, default scanner-guard/bans:
SCANNER_GUARD_HTTP_SERVER_PATH=scanner-guard/bans
```

Each ban is POSTed as JSON (`ip`, `reason`, `matched_value`, `hit_count`, `path`, `banned_at`,
`expires_at`) with `X-Timestamp` and `X-Signature: hash_hmac('sha256', timestamp.body, secret)`.
The central app rejects bad signatures and timestamps outside `http.tolerance` (default 300s) with
`403`, and a replayed signature with `409`. It then records the ban exactly like a local one: its
own salted `ip_hash` in the table, daily stats, and the raw IP in cache only — so its nginx export
covers every satellite.

The satellite sends the request after the response (`defer()`), with `http.timeout` (default 2s);
a failure is logged and never affects the request or the local (cache) ban.

## Configuration

```php
// config/scanner-guard.php
return [
    'enabled' => true,
    'driver' => 'database', // database | http | cache
    'http' => [
        'url' => null,
        'secret' => null,
        'timeout' => 2,
        'tolerance' => 300,
        'server' => ['enabled' => false, 'path' => 'scanner-guard/bans'],
    ],
    'table' => 'scanner_guard_bans',
    'scanner_paths' => [
        'wp-admin*', 'wp-login*', 'xmlrpc.php', '*.git/config', '*phpmyadmin*', /* ... */
    ],
    'ban_threshold' => 3,
    'ban_window' => 300,
    'ban_duration' => 86400,
    'asn_blocklist' => [],
    'store' => null,
    'response_status' => 404,
    'sync_to_nginx' => false,
    'daily_stats_table' => 'scanner_guard_ban_daily_stats',
    'retention_days' => 90,
    'purge_expired_after_days' => 0,
    'auto_prune' => true,
];
```

`scanner_paths` accepts `fnmatch()`-style wildcards matched case-insensitively against the request
path (no leading slash) — extend the array freely for paths specific to your own app.

## Testing

```bash
composer test
```

## Changelog

Please see [CHANGELOG](CHANGELOG.md) for more information on what has changed recently.

## Contributing

Please see [CONTRIBUTING](CONTRIBUTING.md) for details.

## Security

If you discover any security related issues, please email the author instead of using the issue tracker.

## Credits

- [Jefferson Gonçalves](https://github.com/jeffersongoncalves)
- [All Contributors](../../contributors)

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
