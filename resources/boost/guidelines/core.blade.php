## Laravel Scanner Guard

Detects and bans vulnerability-scanner traffic (WordPress/CMS probes, `.git`/config leaks,
phpMyAdmin, ...) that reaches Laravel's router as an ordinary 404, and optionally hard-blocks by
IP/CIDR, User-Agent or ASN (via `jeffersongoncalves/laravel-visitor-fingerprint`).

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

Migrations are only needed for the default `database` driver.

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

- **Path-based ban**: an IP hitting `config('scanner-guard.scanner_paths')` (fnmatch patterns,
  case-insensitive, no leading slash) `ban_threshold` times within `ban_window` seconds gets banned
  for `ban_duration` seconds.
- **404 flood** (opt-in, `not_found_threshold` / `not_found_window`): an IP collecting that many 404s
  is banned with reason `not_found_flood`. Only counts 404s from routes the middleware runs on.
- **Escalation** (opt-in, `escalation` = seconds per offense, last step repeats): repeat offenders
  within `escalation_lookback_days` get longer bans; only `escalation_reasons` count.
- **IP / CIDR blocklist**: `ip_blocklist` (IPv4 + IPv6, `IpUtils::checkIp()`) — rejected before any
  counting, no ban row, never expires, always sent to the sinks (reason `static`).
- **User-Agent blocklist** (opt-in): `user_agent_blocklist` = `block_empty`, fnmatch `patterns`,
  `action` `ban` (records reason `user_agent`) or `reject` (response only).
- **Runtime blocklist** (`database` driver): `Models\ScannerGuardBlocklistEntry` rows (`TYPE_IP`,
  `TYPE_USER_AGENT`) add to the config lists without a redeploy; cached under a version key. After a
  mass `query()->delete()`/`update()` call `ScannerGuard::blocklistChanged()`.
- **ASN blocklist**: `asn_blocklist` (e.g. `['AS16276']`) — resolved through `visitor-fingerprint`'s
  `GeoIpDriver`, so it only works when that package's `geoip.driver` is `ip_api` or `maxmind`.
- **Plain 404 response**: `response_status` defaults to 404, not 403 — a banned scanner can't tell
  it's banned versus the route never existing.
- **Audit trail + stats**: every ban writes a `ScannerGuardBan` row (hashed IP; opt-in
  `store_details` adds the encrypted `$ban->ip` and `$ban->path` for incident investigation, and via
  its env keeps expired rows until `retention_days`) and bumps `scanner_guard_ban_daily_stats`. `ScannerGuard::dailyStats(14)` reads the history;
  `scanner-guard:aggregate-and-prune` (daily unless `auto_prune = false`) reconciles and prunes.
- **Unban**: `ScannerGuard::unban($ipHash)` — deleting the row alone leaves the cached ban active.
- **Drivers**: `driver` = `database` (default), `cache` (cache-only bans) or `http` (satellite
  forwarding bans to a central app over HMAC-signed requests; the central app sets
  `http.server.enabled`, satellites can pull its denylist with `http.pull`).
- **Server agents**: `scanner-guard-agent` (Go binary, nftables) acts as an `http` satellite and
  sends signed heartbeats to `POST {http.server.path}/heartbeat`, stored one row per source in
  `Models\ScannerGuardAgent` (`online()` / `offline()` scopes, `isOnline()`, stale after 300s).
- **Denylist sinks**: `scanner-guard.sinks` lists `Contracts\DenylistSink` classes (separate
  packages: `laravel-scanner-guard-nginx`, `laravel-scanner-guard-cloudflare`; Traefik pulls via
  `laravel-scanner-guard-traefik`). `php artisan scanner-guard:sync-denylist` pushes the static
  `ip_blocklist` + active bans to each, best-effort (it needs a cached raw IP, not the permanent
  hashed record). With sinks set it runs every minute and each ban queues a sync (`sync_on_ban`).

### Configuration

@verbatim
<code-snippet name="Config example" lang="php">
// config/scanner-guard.php
return [
    'enabled' => true,
    'driver' => 'database', // database | http | cache
    'store_details' => false, // needs the add_details migration
    'scanner_paths' => ['wp-admin*', 'wp-login*', 'xmlrpc.php', '*.git/config', /* ... */],
    'ban_threshold' => 3,
    'ban_window' => 300,
    'ban_duration' => 86400,
    'escalation' => [], // e.g. [86400, 604800, 1209600, 2592000, 7776000]
    'not_found_threshold' => null, // e.g. 20
    'ip_blocklist' => [],
    'user_agent_blocklist' => ['block_empty' => false, 'patterns' => [], 'action' => 'ban'],
    'asn_blocklist' => [],
    'store' => null,
    'response_status' => 404,
    'sinks' => [],
];
</code-snippet>
@endverbatim

### Best Practices

- Never add legitimate app routes (e.g. your own admin panel path) to `scanner_paths` — a real
  logged-in user hammering their own dashboard would eventually get banned too.
- Broad UA patterns (`*curl*`) also block your own scripts, uptime monitors and health checks —
  nothing exempts verified crawlers.
- Prefer a durable cache store (`redis`, `file`) over `array` in `scanner-guard.store` if you plan
  to use a denylist sink — an `array` cache never survives past the current request.
- Give each `http` satellite / agent its own secret in `http.secrets`, so its `source` name can be
  trusted.
