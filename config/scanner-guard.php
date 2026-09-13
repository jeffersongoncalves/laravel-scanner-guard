<?php

declare(strict_types=1);

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
    | Table
    |--------------------------------------------------------------------------
    */
    'table' => env('SCANNER_GUARD_TABLE', 'scanner_guard_bans'),

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
    | Cache Store
    |--------------------------------------------------------------------------
    |
    | Cache store used for hit-counting and the ban fast-path lookup. Null
    | uses the app's default store. Prefer a store that survives a plain
    | `cache:clear` invocation (e.g. redis, file) over "array" if you also
    | plan to use the nginx denylist export (see README) — an evicted
    | fast-path entry still leaves the app-layer ban intact (backed by the
    | database), but an evicted raw-IP export entry cannot be recovered.
    |
    */
    'store' => env('SCANNER_GUARD_STORE'),

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
    | Sync to nginx
    |--------------------------------------------------------------------------
    |
    | When true, self-schedules `scanner-guard:export-denylist` daily so your
    | nginx `include`d denylist file stays current. Off by default: writing
    | files to disk on a schedule is more deployment-specific (permissions,
    | shared vs. per-instance storage, whether nginx even reloads the file)
    | than a DB-only aggregate job, so this is left for you to opt into once
    | you've wired the nginx side up (see README).
    |
    */
    'sync_to_nginx' => env('SCANNER_GUARD_SYNC_TO_NGINX', false),

];
