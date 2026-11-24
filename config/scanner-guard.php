<?php

declare(strict_types=1);

use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardBan;

return [

    /*
    |--------------------------------------------------------------------------
    | Enabled
    |--------------------------------------------------------------------------
    |
    | Master switch for the BlockScannerRequests middleware. Flip off without
    | removing the middleware from your routes/kernel.
    |
    */
    'enabled' => env('SCANNER_GUARD_ENABLED', true),

    /*
    |--------------------------------------------------------------------------
    | Driver
    |--------------------------------------------------------------------------
    |
    | Where bans are persisted:
    |
    | - "database": audit rows + daily stats in SQL (needs the migrations).
    | - "http": bans stay in the cache store and are forwarded to a central
    |   app (running the "database" driver with http.server.enabled) over
    |   an HMAC-signed request. No SQL database needed here.
    | - "cache": bans live only in the cache store for ban_duration. No
    |   audit trail, stats, denylist sinks or survival of a cache flush.
    |
    | aggregate-and-prune only runs with "database"; sync-denylist with
    | "database" or "http" (from the last pull).
    |
    */
    'driver' => env('SCANNER_GUARD_DRIVER', 'database'),

    /*
    |--------------------------------------------------------------------------
    | HTTP Driver
    |--------------------------------------------------------------------------
    |
    | Client side (driver = "http"): url + secret of the central app. The
    | call is sent after the response, with a short timeout; failures are
    | logged and never affect the request.
    |
    | Server side (central app): enable the route that receives forwarded
    | bans. Requests are signed with
    | hash_hmac('sha256', X-Timestamp.body, secret), rejected outside
    | `tolerance` seconds and never accepted twice.
    |
    | `pull` (satellite): schedules scanner-guard:pull-denylist every minute,
    | fetching the central app's active bans, ip_blocklist and user-agent
    | patterns from a GET on `url`. A failed pull keeps the last list; with
    | `sinks` configured each pull also re-syncs this app's sinks.
    |
    | `source` names this satellite in every forwarded ban (null = app.name);
    | the central app stores it in the ban's `source` column (needs the
    | add_source migration there). Null `source` on a row = banned locally.
    |
    | `secrets` (central app only): per-source secrets, e.g.
    | ['shop' => env('SCANNER_GUARD_SECRET_SHOP')]. A listed source is only
    | accepted when signed with its own secret, so one satellite can't
    | forward bans under another's name. Unlisted sources fall back to
    | `secret`; leave `secret` empty to accept listed sources only.
    |
    */
    'http' => [
        'url' => env('SCANNER_GUARD_HTTP_URL'),
        'secret' => env('SCANNER_GUARD_HTTP_SECRET'),
        'source' => env('SCANNER_GUARD_HTTP_SOURCE'),
        'pull' => env('SCANNER_GUARD_HTTP_PULL', false),
        'secrets' => [],
        'timeout' => env('SCANNER_GUARD_HTTP_TIMEOUT', 2),
        'tolerance' => env('SCANNER_GUARD_HTTP_TOLERANCE', 300),

        'server' => [
            'enabled' => env('SCANNER_GUARD_HTTP_SERVER_ENABLED', false),
            'path' => env('SCANNER_GUARD_HTTP_SERVER_PATH', 'scanner-guard/bans'),
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Table
    |--------------------------------------------------------------------------
    */
    'table' => env('SCANNER_GUARD_TABLE', 'scanner_guard_bans'),

    /*
    |--------------------------------------------------------------------------
    | Store Details
    |--------------------------------------------------------------------------
    |
    | Opt-in, for incident investigation. Also keeps in each ban row the IP
    | ($ban->ip, encrypted with the app key) and the request path without
    | its query string ($ban->path). Off (default): the table only ever
    | holds a salted hash of the IP. Needs the add_details migration; set it
    | on the central app with the "http" driver.
    |
    | Turning it on through the env also keeps expired rows until
    | retention_days (see purge_expired_after_days). Rotating APP_KEY needs
    | the old key in APP_PREVIOUS_KEYS to read stored IPs.
    |
    */
    'store_details' => env('SCANNER_GUARD_STORE_DETAILS', false),

    /*
    |--------------------------------------------------------------------------
    | Scanner Paths
    |--------------------------------------------------------------------------
    |
    | fnmatch()-style patterns (case-insensitive), matched against the request
    | path with no leading slash (e.g. "wp-admin/setup-config.php"). This list
    | only ever sees requests that already reached Laravel's router as an
    | ordinary 404 — see the README for the category of scanner traffic
    | (literal nonexistent .php files failing at nginx/PHP-FPM) this package
    | cannot and does not attempt to catch.
    |
    | This default list is WordPress/CMS-probe heavy since that's the bulk of
    | real-world scanner noise, plus a handful of generic credential/config/
    | RCE probe paths. Extend it freely for your own app — just append more
    | patterns, no other wiring required.
    |
    */
    'scanner_paths' => [
        // WordPress
        'wp-admin*',
        'wp-login*',
        'wp-json*',
        'wp-content*',
        'wp-includes*',
        'wordpress*',
        'xmlrpc.php',

        // Version control / config leaks
        '*.git/config',
        '*.git/HEAD',
        '.env*',
        '.docker/*',
        '.aws/*',
        '.vscode/sftp.json',
        'config.json',

        // Admin / DB tooling probes
        '*phpmyadmin*',
        '*pma*',
        'adminer*.php',
        'phpinfo.php',

        // Framework / dependency probes
        'vendor/phpunit/*',
        '_ignition/execute-solution',
        'laravel/.env',

        // Misc well-known scanner targets
        'server-status',
        'server-info',
        'cgi-bin/*',
        'actuator/*',
        'owa/auth/logon.jsp',
        'sitecore/*',
        'umbraco/*',
        'jenkins/*',
        'solr/*',
        'geoserver/*',
        'ALFA_DATA/*',
    ],

    /*
    |--------------------------------------------------------------------------
    | Ban Threshold / Window / Duration
    |--------------------------------------------------------------------------
    |
    | An IP gets banned once it racks up `ban_threshold` hits against
    | `scanner_paths` within a rolling `ban_window` seconds. The ban itself
    | then lasts `ban_duration` seconds.
    |
    */
    'ban_threshold' => env('SCANNER_GUARD_BAN_THRESHOLD', 3),

    'ban_window' => env('SCANNER_GUARD_BAN_WINDOW', 300),

    'ban_duration' => env('SCANNER_GUARD_BAN_DURATION', 86400),

    /*
    |--------------------------------------------------------------------------
    | Escalation
    |--------------------------------------------------------------------------
    |
    | Opt-in. Ban duration in seconds per offense (1st, 2nd, 3rd, ...); past
    | the last step the last entry repeats. An offense counts when the same
    | IP had a ban for one of `escalation_reasons` within
    | `escalation_lookback_days`. Empty (default) = off: every ban lasts
    | ban_duration. E.g. 1d → 7d → 14d → 30d → 90d:
    |
    |   [86400, 604800, 1209600, 2592000, 7776000]
    |
    | Needs the add_offense migration with the "database" driver. With
    | "cache"/"http" the count lives in the cache store and resets on a
    | cache flush. With escalation on, aggregate-and-prune keeps each IP's
    | latest ban inside the lookback, so shortening retention can't erase it.
    |
    */
    'escalation' => [],

    'escalation_lookback_days' => env('SCANNER_GUARD_ESCALATION_LOOKBACK_DAYS', 365),

    'escalation_reasons' => [
        ScannerGuardBan::REASON_SCANNER_PATH,
        ScannerGuardBan::REASON_NOT_FOUND_FLOOD,
        ScannerGuardBan::REASON_USER_AGENT,
    ],

    /*
    |--------------------------------------------------------------------------
    | 404 Flood
    |--------------------------------------------------------------------------
    |
    | Opt-in. Bans an IP after `not_found_threshold` 404 responses within
    | `not_found_window` seconds, catching scanners probing for software
    | `scanner_paths` doesn't list. Null (default) = off. Keep the threshold
    | high (e.g. 20 in 60s): a visitor following a few dead links never gets
    | near it, a scanner fires dozens per minute. The 404 that trips it is
    | still served normally; the ban applies from the next request.
    |
    */
    'not_found_threshold' => env('SCANNER_GUARD_NOT_FOUND_THRESHOLD'),

    'not_found_window' => env('SCANNER_GUARD_NOT_FOUND_WINDOW', 60),

    /*
    |--------------------------------------------------------------------------
    | ASN Blocklist
    |--------------------------------------------------------------------------
    |
    | Opt-in. Array of ASN strings (e.g. "AS16276" for OVH SAS) to hard-block
    | immediately, regardless of path. Resolved via
    | jeffersongoncalves/laravel-visitor-fingerprint's GeoIpDriver — only
    | the "ip_api" and "maxmind" drivers populate an ASN; the default
    | "headers" driver does not, so this list is a no-op unless you also
    | configure visitor-fingerprint.geoip.driver accordingly. Empty by
    | default: this is a decision only you can make for your own traffic.
    |
    */
    'asn_blocklist' => [],

    /*
    |--------------------------------------------------------------------------
    | IP Blocklist
    |--------------------------------------------------------------------------
    |
    | Permanent block for IPs and CIDR ranges (IPv4 + IPv6) you have already
    | identified, e.g. '185.177.72.69' or '185.177.72.0/24'. Rejected with
    | response_status before any counting, no ban row written, never
    | expires. Every denylist sink always gets them (reason "static"), so
    | with a sink configured they never reach PHP. Invalid entries are
    | skipped before the sync so they can't break a sink (e.g. nginx -t).
    |
    */
    'ip_blocklist' => [],

    /*
    |--------------------------------------------------------------------------
    | User-Agent Blocklist
    |--------------------------------------------------------------------------
    |
    | Opt-in, empty by default: a UA rule is a decision only you can make for
    | your own traffic. `block_empty` catches a missing/blank User-Agent.
    | `patterns` are fnmatch()-style, case-insensitive, matched against the
    | full UA string as-is — nothing exempts verified crawlers, and a broad
    | pattern like '*curl*' also locks out your own scripts and monitors.
    | `action`: "reject" (respond with response_status) or "ban" (reject and
    | record a ban with reason "user_agent", so it escalates and reaches the
    | denylist sinks like any other ban).
    |
    */
    'user_agent_blocklist' => [
        'block_empty' => env('SCANNER_GUARD_BLOCK_EMPTY_USER_AGENT', false),
        'patterns' => [
            // 'zgrab*',
            // '*masscan*',
        ],
        'action' => env('SCANNER_GUARD_USER_AGENT_ACTION', 'ban'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Cache Store
    |--------------------------------------------------------------------------
    |
    | Cache store used for hit-counting and the ban fast-path lookup. Null
    | uses the app's default store. Prefer a store that survives a plain
    | `cache:clear` invocation (e.g. redis, file) over "array" if you also
    | plan to use a denylist sink (see README) — an evicted fast-path entry
    | still leaves the app-layer ban intact (backed by the database), but an
    | evicted raw-IP entry cannot be recovered, so that ban leaves the sinks.
    |
    | With several app servers, use a store they all share (e.g. redis):
    | hit counters and the one-ban-per-burst guard only coordinate
    | requests that see the same store.
    |
    */
    'store' => env('SCANNER_GUARD_STORE'),

    /*
    |--------------------------------------------------------------------------
    | Negative Cache TTL
    |--------------------------------------------------------------------------
    |
    | Seconds a "not banned" answer from the database fallback stays cached,
    | so non-banned traffic doesn't cost a query per request. A ban written
    | through ban() on a shared cache takes effect immediately; a ban only
    | visible in the database (e.g. after a cache flush on another node)
    | takes up to this long. 0 disables it.
    |
    */
    'negative_cache_ttl' => env('SCANNER_GUARD_NEGATIVE_CACHE_TTL', 60),

    /*
    |--------------------------------------------------------------------------
    | Response Status
    |--------------------------------------------------------------------------
    |
    | Deliberately a plain 404 by default rather than 403 — a banned scanner
    | can't distinguish "banned" from "this route never existed" and adjust
    | its behavior accordingly.
    |
    */
    'response_status' => env('SCANNER_GUARD_RESPONSE_STATUS', 404),

    /*
    |--------------------------------------------------------------------------
    | Denylist Sinks
    |--------------------------------------------------------------------------
    |
    | Classes implementing Contracts\DenylistSink that block banned IPs before
    | they reach PHP. Each gets the full list (valid ip_blocklist entries +
    | active bans) from `scanner-guard:sync-denylist`, which self-schedules
    | every minute once this list is non-empty (so expired bans drop off),
    | and also runs from the pull on http satellites. Empty by default.
    | Official sinks ship as separate packages:
    |
    |   - jeffersongoncalves/laravel-scanner-guard-nginx       (deny file)
    |   - jeffersongoncalves/laravel-scanner-guard-apache      (Require file)
    |   - jeffersongoncalves/laravel-scanner-guard-caddy       (abort snippet)
    |   - jeffersongoncalves/laravel-scanner-guard-frankenphp  (abort snippet)
    |   - jeffersongoncalves/laravel-scanner-guard-cloudflare  (Custom IP List)
    |
    | Traefik pulls instead of being pushed to:
    | jeffersongoncalves/laravel-scanner-guard-traefik serves the list to its
    | HTTP provider and needs no entry here.
    |
    | `sync_on_ban` queues a (unique) sync job on every new ban, so sinks
    | follow the ban table within seconds; unban() and runtime blocklist
    | changes always queue one. Syncs share a cache lock, so they never
    | overlap, and a failing sink is logged without stopping the others.
    |
    */
    'sinks' => [
        // \JeffersonGoncalves\ScannerGuardNginx\NginxSink::class,
        // \JeffersonGoncalves\ScannerGuardApache\ApacheSink::class,
        // \JeffersonGoncalves\ScannerGuardCaddy\CaddySink::class,
        // \JeffersonGoncalves\ScannerGuardFrankenPhp\FrankenPhpSink::class,
        // \JeffersonGoncalves\ScannerGuardCloudflare\CloudflareSink::class,
    ],

    'sync_on_ban' => env('SCANNER_GUARD_SYNC_ON_BAN', true),

    /*
    |--------------------------------------------------------------------------
    | Daily Stats Table
    |--------------------------------------------------------------------------
    |
    | One row per day, keyed by the day each ban was created. Counters are
    | bumped at ban time and reconciled daily by
    | scanner-guard:aggregate-and-prune, so the history survives purges,
    | unbans and pruning of the ban rows.
    |
    */
    'daily_stats_table' => env('SCANNER_GUARD_DAILY_STATS_TABLE', 'scanner_guard_ban_daily_stats'),

    /*
    |--------------------------------------------------------------------------
    | Retention
    |--------------------------------------------------------------------------
    |
    | Expired ban rows older than this many days are pruned by
    | scanner-guard:aggregate-and-prune after being folded into
    | daily_stats_table. Separate from ban_duration, which controls how long
    | a ban stays active, not how long its audit row survives after expiring.
    |
    */
    'retention_days' => env('SCANNER_GUARD_RETENTION_DAYS', 90),

    /*
    |--------------------------------------------------------------------------
    | Purge Expired After Days
    |--------------------------------------------------------------------------
    |
    | scanner-guard:aggregate-and-prune deletes bans that expired at least
    | this many days ago (0 = on the next run), once their day is recorded
    | in daily_stats_table. Set to null to keep expired rows until
    | retention_days instead. Defaults to null with
    | SCANNER_GUARD_STORE_DETAILS on, so the history survives the ban.
    |
    */
    'purge_expired_after_days' => env('SCANNER_GUARD_PURGE_EXPIRED_AFTER_DAYS', env('SCANNER_GUARD_STORE_DETAILS', false) ? null : 0),

    /*
    |--------------------------------------------------------------------------
    | Auto Prune
    |--------------------------------------------------------------------------
    |
    | When true, self-schedules scanner-guard:aggregate-and-prune daily so
    | scanner_guard_bans doesn't grow unbounded. On by default: unlike the
    | denylist sinks, writing to the DB has no deployment-specific footgun.
    |
    */
    'auto_prune' => env('SCANNER_GUARD_AUTO_PRUNE', true),

];
