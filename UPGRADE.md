# Upgrade Guide

## From 1.x to 2.0

The nginx export moved out of this package. Version 2.0 pushes the denylist to pluggable **sinks**
instead; nginx is now one of them, shipped as
[`jeffersongoncalves/laravel-scanner-guard-nginx`](https://github.com/jeffersongoncalves/laravel-scanner-guard-nginx).
Nothing else changed: middleware, drivers, bans, escalation, blocklists and stats work as before.

### Using the nginx export (`sync_to_nginx` was on)

1. Install the nginx sink:

   ```bash
   composer require jeffersongoncalves/laravel-scanner-guard:^2.0 jeffersongoncalves/laravel-scanner-guard-nginx
   ```

2. In a published `config/scanner-guard.php`, replace `sync_to_nginx` and the whole `nginx` block
   with:

   ```php
   'sinks' => [
       \JeffersonGoncalves\ScannerGuardNginx\NginxSink::class,
   ],

   'sync_on_ban' => env('SCANNER_GUARD_SYNC_ON_BAN', true),
   ```

3. Environment variables:

   | 1.x | 2.0 |
   |---|---|
   | `SCANNER_GUARD_SYNC_TO_NGINX=true` | remove it: a non-empty `sinks` turns the sync on |
   | `SCANNER_GUARD_NGINX_EXPORT_ON_BAN` | `SCANNER_GUARD_SYNC_ON_BAN` |
   | `SCANNER_GUARD_NGINX_PATH` | unchanged, now read by the nginx package |
   | `SCANNER_GUARD_NGINX_RELOAD_COMMAND` | unchanged, now read by the nginx package |

   The nginx package writes the same file, same lines (`deny <ip>; # ...`), at the same default
   path (`storage/app/scanner-guard/denylist.conf`), so the nginx `include` stays as it is.

4. Rename the command in anything that calls it (cron entries, deploy scripts, supervisor):
   `scanner-guard:export-denylist` → `scanner-guard:sync-denylist`. The `--path` option is gone:
   set `scanner-guard-nginx.path` (env `SCANNER_GUARD_NGINX_PATH`) instead.

### Not using the nginx export

Drop `sync_to_nginx` and `nginx` from a published config, if present. That's it.

### Renamed classes

| 1.x | 2.0 |
|---|---|
| `Console\Commands\ExportDenylistCommand` | `Console\Commands\SyncDenylistCommand` |
| `Jobs\ExportDenylist` | `Jobs\SyncDenylist` |
| log `scanner-guard: failed to queue nginx export` | `scanner-guard: failed to queue denylist sync` |

Invalid `ip_blocklist` entries are now logged as a warning (`scanner-guard: skipped invalid
ip_blocklist entry`) instead of printed by the export command.

### New

- `Contracts\DenylistSink`: implement `sync(array $entries)` to push the denylist anywhere.
- `ScannerGuard::denylistEntries()`: the list every sink receives.
- [`laravel-scanner-guard-cloudflare`](https://github.com/jeffersongoncalves/laravel-scanner-guard-cloudflare):
  blocks at the Cloudflare edge through a Custom IP List.
- [`laravel-scanner-guard-traefik`](https://github.com/jeffersongoncalves/laravel-scanner-guard-traefik):
  serves the denylist to Traefik's HTTP provider.
