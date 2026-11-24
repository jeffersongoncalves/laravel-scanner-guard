<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardBan;
use JeffersonGoncalves\ScannerGuard\ScannerGuard;

beforeEach(function () {
    $this->guard = app(ScannerGuard::class);
});

it('stores no details by default', function () {
    $this->guard->ban('203.0.113.60', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3, 'wp-admin');

    expect(ScannerGuardBan::query()->sole())->ip->toBeNull()->path->toBeNull();
});

it('leaves the detail columns out of the insert by default, so the migration is optional', function () {
    DB::enableQueryLog();
    $this->guard->ban('203.0.113.61', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);

    $insert = collect(DB::getQueryLog())->pluck('query')
        ->first(fn (string $sql): bool => str_starts_with($sql, 'insert') && str_contains($sql, 'ip_hash'));

    expect($insert)->not->toBeNull()
        ->and(preg_match('/["`](ip|path)["`]/', $insert))->toBe(0);
});

it('stores the ip encrypted when enabled, readable after the ban expires', function (string $ip) {
    config(['scanner-guard.store_details' => true]);

    $ban = $this->guard->ban($ip, ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);

    expect(DB::table('scanner_guard_bans')->value('ip'))->not->toContain($ip);

    $this->travelTo($ban->expires_at->copy()->addSecond());

    expect($this->guard->rawIpFor($ban->ip_hash))->toBeNull()
        ->and(ScannerGuardBan::query()->sole()->ip)->toBe($ip);
})->with(['203.0.113.62', '2001:db8:85a3:1111:2222:8a2e:370:7334']);

it('never serializes the stored ip', function () {
    config(['scanner-guard.store_details' => true]);

    $this->guard->ban('203.0.113.63', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);

    expect(ScannerGuardBan::query()->sole()->toArray())->not->toHaveKey('ip');
});

it('stores the ip of a forwarded ban on the central app', function () {
    config(['scanner-guard.store_details' => true]);

    $this->guard->recordForwardedBan('203.0.113.64', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3, now(), now()->addDay(), source: 'shop');

    expect(ScannerGuardBan::query()->sole()->ip)->toBe('203.0.113.64');
});

it('stores the path, whatever bytes the attacker sent', function (string $path, string $stored) {
    config(['scanner-guard.store_details' => true]);

    $this->guard->ban('203.0.113.65', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3, $path);

    expect(ScannerGuardBan::query()->sole()->path)->toBe($stored);
})->with([
    'plain' => ['wp-admin/setup-config.php', 'wp-admin/setup-config.php'],
    'nul and invalid utf-8' => ["wp-admin/\0a\xFFb", 'wp-admin/a%FFb'],
    'valid utf-8' => ['wp-admin/é', 'wp-admin/é'],
    'query string' => ['wp-admin/install.php?token=secret', 'wp-admin/install.php'],
    'too long' => [str_repeat('a', 5000), str_repeat('a', 2048)],
]);

it('stores the path of the banning request without its query string', function () {
    config(['scanner-guard.store_details' => true, 'scanner-guard.ban_threshold' => 1]);
    Route::get('/wp-admin/{any}', fn () => 'ok')->middleware('scanner-guard');

    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.66'])->get('/wp-admin/install.php?token=secret')->assertNotFound();

    expect(ScannerGuardBan::query()->sole()->path)->toBe('wp-admin/install.php');
});

it('keeps expired bans by default once details are turned on through the env', function (array $env, mixed $expected) {
    $original = [];

    foreach ($env as $key => $value) {
        $original[$key] = [getenv($key), array_key_exists($key, $_ENV), $_ENV[$key] ?? null];
        putenv("{$key}={$value}");
        $_ENV[$key] = $value;
    }

    try {
        expect((require __DIR__.'/../../config/scanner-guard.php')['purge_expired_after_days'])->toBe($expected);
    } finally {
        foreach ($original as $key => [$process, $inEnv, $value]) {
            putenv($process === false ? $key : "{$key}={$process}");

            if ($inEnv) {
                $_ENV[$key] = $value;
            } else {
                unset($_ENV[$key]);
            }
        }
    }
})->with([
    'off' => [[], 0],
    'on' => [['SCANNER_GUARD_STORE_DETAILS' => 'true'], null],
    'on, explicit days win' => [['SCANNER_GUARD_STORE_DETAILS' => 'true', 'SCANNER_GUARD_PURGE_EXPIRED_AFTER_DAYS' => '7'], '7'],
]);
