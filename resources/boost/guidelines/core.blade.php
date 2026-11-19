## Laravel Scanner Guard

Detects and bans vulnerability-scanner traffic (WordPress/CMS probes, `.git`/config leaks,
phpMyAdmin, ...) that reaches Laravel's router as an ordinary 404, and optionally hard-blocks by
ASN via `jeffersongoncalves/laravel-visitor-fingerprint`.

### Scope — read this before assuming it "isn't working"

This package only sees requests that already reach Laravel's front controller. Literal nonexistent
`.php` file requests (`/wp/index.php`) fail at nginx/PHP-FPM *before* Laravel boots — no PHP code
can intercept those. Fix that category with `try_files $uri =404;` in your nginx PHP location
block, not with this package.

### Installation

@verbatim
<code-snippet name="Install the package" lang="bash">
composer require jeffersongoncalves/laravel-scanner-guard
php artisan vendor:publish --tag="scanner-guard-config"
php artisan migrate
</code-snippet>
@endverbatim

### Enabling protection

The `scanner-guard` middleware alias is registered but never auto-attached — opt in explicitly:

@verbatim
<code-snippet name="Attach the middleware" lang="php">
use JeffersonGoncalves\ScannerGuard\Http\Middleware\BlockScannerRequests;

->withMiddleware(function (Middleware $middleware) {
    $middleware->appendToGroup('web', BlockScannerRequests::class);
})
</code-snippet>
@endverbatim

### Features

- **Path-based ban**: an IP hitting `config('scanner-guard.scanner_paths')` (fnmatch patterns)
  `ban_threshold` times within `ban_window` seconds gets banned for `ban_duration` seconds.
- **ASN blocklist**: hard-block an entire ASN immediately via `config('scanner-guard.asn_blocklist')`
  (e.g. `['AS16276']`) — resolved through `visitor-fingerprint`'s `GeoIpDriver`, so it only has any
  effect when that package's `geoip.driver` is `ip_api` or `maxmind` (not the default `headers`).
- **Plain 404 response**: `response_status` defaults to 404, not 403 — a banned scanner can't tell
  it's banned versus the route never existing.
- **Audit trail**: every ban writes a `ScannerGuardBan` row (hashed IP only, never raw) with the
  default `database` driver.
- **No-database drivers**: `driver` = `cache` (cache-only bans) or `http` (forward bans to a central
  app over HMAC-signed requests; that app enables `http.server.enabled`). Migrations and stats are
  `database`-only.
- **Denylist sinks**: `scanner-guard.sinks` lists `Contracts\DenylistSink` classes (separate
  packages: `laravel-scanner-guard-nginx`, `laravel-scanner-guard-cloudflare`; Traefik pulls via
  `laravel-scanner-guard-traefik`). `php artisan scanner-guard:sync-denylist` pushes the static
  `ip_blocklist` + active bans to each, best-effort (see the package README's "Privacy tradeoff":
  it needs a cached raw IP, not the permanent hashed record). With sinks set it runs every minute
  and each ban queues a sync (`sync_on_ban`).

### Configuration

@verbatim
<code-snippet name="Config example" lang="php">
// config/scanner-guard.php
return [
    'enabled' => true,
    'driver' => 'database', // database | http | cache
    'scanner_paths' => ['wp-admin*', 'wp-login*', 'xmlrpc.php', '*.git/config', /* ... */],
    'ban_threshold' => 3,
    'ban_window' => 300,
    'ban_duration' => 86400,
    'asn_blocklist' => [],
    'response_status' => 404,
];
</code-snippet>
@endverbatim

### Best Practices

- Never add legitimate app routes (e.g. your own admin panel path) to `scanner_paths` — a real
  logged-in user hammering their own dashboard would eventually get banned too.
- Prefer a durable cache store (`redis`, `file`) over `array` in `scanner-guard.store` if you plan
  to use a denylist sink — an `array` cache never survives past the current request.
