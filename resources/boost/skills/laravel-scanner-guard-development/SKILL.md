---
name: laravel-scanner-guard-development
description: Extend or debug JeffersonGoncalves\ScannerGuard — scanner path patterns, ban lifecycle, ASN blocklisting, and the nginx denylist export.
---

# Laravel Scanner Guard Development

## When to use this skill

Use this skill when:

- Adding/tuning `scanner_paths` patterns for a specific app's traffic
- Debugging why an IP was (or wasn't) banned
- Working with the nginx denylist export and its cache-eviction tradeoff
- Extending `ScannerGuard`'s ban/hit-counting logic

## Core Concepts

### Two categories of scanner traffic

1. Literal nonexistent `.php` files — fail at nginx/PHP-FPM, never reach PHP. Not this package's
   job; fix with `try_files $uri =404;`.
2. Extension-less/routable paths that reach Laravel's router as an ordinary 404 — this package's
   entire job.

Never try to "fix" category 1 from inside `BlockScannerRequests` — it's structurally invisible to
PHP.

### Ban lifecycle

```
request -> isBanned()? -----------------------------> yes: abort(response_status)
        -> asn_blocklist non-empty? -> isAsnBlocked()? -> yes: ban() + abort(response_status)
        -> matchScannerPath()? ----------------------> no: pass through
        -> registerHit() >= ban_threshold? -----------> yes: ban() + abort(response_status)
        -> pass through
```

`isBanned()` checks cache first (fast path), then falls back to the `scanner_guard_bans` table if
the cache entry is missing — and re-hydrates the cache when it finds an active DB row. This means
a `cache:clear` never silently un-bans anyone; it only costs one extra DB query per previously
cached-but-now-uncached IP.

### Privacy: hashed DB, raw IP only in cache

`ScannerGuardBan::ip_hash` is `IpAnonymizer::hash($ip)` (salted sha256, from
`jeffersongoncalves/laravel-visitor-fingerprint`) — irreversible by design. The raw IP is cached
separately at ban time (`scanner-guard:raw-ip:{hash}`, TTL = `ban_duration`) purely so
`scanner-guard:export-denylist` can write a real nginx `deny` line. If that cache entry is gone
(flush, eviction, "array" driver), the export skips that ban — the app-layer protection is
unaffected (it only needs the hash), only the nginx-side export lags.

```php
use JeffersonGoncalves\ScannerGuard\ScannerGuard;

$scannerGuard = app(ScannerGuard::class);
$scannerGuard->ban($ip, ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', hitCount: 3, path: $path);
$scannerGuard->rawIpFor($scannerGuard->hashIp($ip)); // string|null
```

## Common Patterns

### Adding app-specific scanner paths

```php
// config/scanner-guard.php
'scanner_paths' => array_merge(
    config('scanner-guard.scanner_paths'),
    ['my-legacy-admin/*', 'old-api/v1/*'],
),
```

### Testing middleware behavior

Use `withServerVariables(['REMOTE_ADDR' => $ip])` to control the IP per test request — `TestCase`
uses the `array` cache driver by default, so each test run starts clean. To simulate an ASN-blocked
IP, bind a fake `GeoIpDriver` before the request:

```php
app()->bind(GeoIpDriver::class, fn () => new class implements GeoIpDriver {
    public function resolve(string $ip): GeoLocation
    {
        return new GeoLocation(asn: 'AS16276 OVH SAS');
    }
});
```

## Troubleshooting

### A legitimate user got banned

Check `ScannerGuardBan::query()->where('ip_hash', $hash)->first()` for the `matched_value` pattern
that triggered it — it's almost always an overly broad `scanner_paths` entry matching a real route
in the host app. Narrow the pattern rather than raising `ban_threshold` globally.

### The nginx export is missing entries I know are banned

Expected when the cache store doesn't retain the `scanner-guard:raw-ip:{hash}` entry for the full
`ban_duration` (an `array` driver, a `cache:clear`, LRU eviction). Switch `scanner-guard.store` to a
durable store (`redis`/`file`) if the nginx export matters to you.

## API Reference

### `ScannerGuard::isBanned(string $ip): bool`

Cache-first, DB-fallback check. Re-hydrates cache on a DB hit.

### `ScannerGuard::matchScannerPath(string $path): ?string`

Returns the matched `fnmatch()` pattern, or `null`.

### `ScannerGuard::registerHit(string $ip): int`

Increments and returns the rolling hit counter (TTL = `ban_window`).

### `ScannerGuard::ban(string $ip, string $reason, string $matchedValue, int $hitCount, ?string $path = null): ScannerGuardBan`

Writes the cache ban + raw-IP cache entry + the permanent DB row, and logs a WARNING-level
`scanner-guard: banned ip` line (includes the raw IP — this log line is the one deliberate
exception to "never log a raw IP" in this ecosystem, since it's operational security telemetry, not
persisted user data).

### `ScannerGuard::rawIpFor(string $ipHash): ?string`

Best-effort raw IP lookup for the export command.
