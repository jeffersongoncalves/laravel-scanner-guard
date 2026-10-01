<?php

declare(strict_types=1);

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardBan;
use JeffersonGoncalves\ScannerGuard\ScannerGuard;
use JeffersonGoncalves\ScannerGuard\ScannerGuardServiceProvider;

beforeEach(function () {
    $this->scannerGuard = app(ScannerGuard::class);

    config([
        'scanner-guard.http.url' => 'https://central.test/scanner-guard/bans',
        'scanner-guard.http.secret' => 'shared-secret',
    ]);
});

/**
 * @return array{0: string, 1: array<string, string>}
 */
function signedBan(ScannerGuard $scannerGuard, array $overrides = [], ?int $timestamp = null): array
{
    $body = (string) json_encode(array_merge([
        'ip' => '198.51.100.7',
        'reason' => ScannerGuardBan::REASON_SCANNER_PATH,
        'matched_value' => 'wp-admin*',
        'hit_count' => 3,
        'path' => 'wp-admin',
        'banned_at' => now()->toIso8601String(),
        'expires_at' => now()->addDay()->toIso8601String(),
    ], $overrides));
    $timestamp = (string) ($timestamp ?? now()->timestamp);

    return [$body, [
        'X-Timestamp' => $timestamp,
        'X-Signature' => $scannerGuard->sign($timestamp, $body),
        'Content-Type' => 'application/json',
        'Accept' => 'application/json',
    ]];
}

function postBan(array $signed)
{
    [$body, $headers] = $signed;

    // call() ignores withHeaders(), so pass them as server vars.
    $server = collect($headers)
        ->mapWithKeys(fn ($value, $key) => ['HTTP_'.strtoupper(str_replace('-', '_', $key)) => $value])
        ->put('CONTENT_TYPE', 'application/json')
        ->all();

    return test()->call('POST', '/scanner-guard/bans', [], [], [], $server, $body);
}

function enableServerRoute(): void
{
    config(['scanner-guard.http.server.enabled' => true]);
    (new ScannerGuardServiceProvider(app()))->packageBooted();
}

it('keeps cache-driver bans in the cache only, with no database writes', function () {
    config(['scanner-guard.driver' => 'cache']);
    $ip = '10.20.0.1';

    expect($this->scannerGuard->ban($ip, ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3))->toBeNull();
    expect($this->scannerGuard->isBanned($ip))->toBeTrue();
    expect(ScannerGuardBan::query()->count())->toBe(0);

    Cache::flush();

    expect($this->scannerGuard->isBanned($ip))->toBeFalse();
});

it('forwards http-driver bans with a valid hmac signature after the response', function () {
    config(['scanner-guard.driver' => 'http']);
    Http::fake();
    $this->withoutDefer();

    $ip = '10.20.0.2';

    expect($this->scannerGuard->ban($ip, ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3, 'wp-admin'))->toBeNull();
    expect($this->scannerGuard->isBanned($ip))->toBeTrue();
    expect(ScannerGuardBan::query()->count())->toBe(0);

    Http::assertSent(function (Request $request) use ($ip): bool {
        $timestamp = $request->header('X-Timestamp')[0];

        return $request->url() === 'https://central.test/scanner-guard/bans'
            && $request['ip'] === $ip
            && $request['hit_count'] === 3
            && $request->header('X-Signature')[0] === $this->scannerGuard->sign($timestamp, $request->body());
    });
});

it('never lets a failing remote call break the ban', function () {
    config(['scanner-guard.driver' => 'http']);
    Http::fake(fn () => throw new RuntimeException('connection refused'));
    $this->withoutDefer();

    $ip = '10.20.0.3';
    $this->scannerGuard->ban($ip, ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);

    expect($this->scannerGuard->isBanned($ip))->toBeTrue();
});

it('records a signed forwarded ban on the central app', function () {
    enableServerRoute();

    postBan(signedBan($this->scannerGuard))->assertCreated();

    $ban = ScannerGuardBan::query()->sole();
    expect($ban->ip_hash)->toBe($this->scannerGuard->hashIp('198.51.100.7'));
    expect($this->scannerGuard->rawIpFor($ban->ip_hash))->toBe('198.51.100.7');
    expect($this->scannerGuard->isBanned('198.51.100.7'))->toBeTrue();
    expect($this->scannerGuard->dailyStats(1)->last()['bans_count'])->toBe(1);
});

it('rejects forwarded bans with a bad signature, a stale timestamp or a replay', function () {
    enableServerRoute();

    [$body, $headers] = signedBan($this->scannerGuard);
    postBan([$body, ['X-Signature' => 'nope'] + $headers])->assertForbidden();

    postBan(signedBan($this->scannerGuard, [], now()->subMinutes(10)->timestamp))->assertForbidden();

    $signed = signedBan($this->scannerGuard);
    postBan($signed)->assertCreated();
    postBan($signed)->assertStatus(409);

    expect(ScannerGuardBan::query()->count())->toBe(1);
});

it('rejects an unknown driver before touching the cache', function () {
    config(['scanner-guard.driver' => 'redis']);

    expect(fn () => $this->scannerGuard->ban('10.20.0.4', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3))
        ->toThrow(InvalidArgumentException::class);
    expect($this->scannerGuard->isBanned('10.20.0.4'))->toBeFalse();
});

it('does not consume the signature of a payload that fails validation', function () {
    enableServerRoute();

    $signed = signedBan($this->scannerGuard, ['ip' => 'not-an-ip']);

    postBan($signed)->assertUnprocessable();
    postBan($signed)->assertUnprocessable();
});

it('does not register the receiving route unless enabled', function () {
    postBan(signedBan($this->scannerGuard))->assertNotFound();
});

it('skips the database-only commands and schedule for other drivers', function () {
    config(['scanner-guard.driver' => 'cache']);

    $this->artisan('scanner-guard:aggregate-and-prune')->expectsOutputToContain('Skipped')->assertSuccessful();
    $this->artisan('scanner-guard:export-denylist')->expectsOutputToContain('Skipped')->assertSuccessful();

    putenv('SCANNER_GUARD_DRIVER=cache');
    $_ENV['SCANNER_GUARD_DRIVER'] = 'cache';

    try {
        $this->refreshApplication();

        $event = collect(app(Schedule::class)->events())->first(
            fn ($event) => str_contains($event->command ?? '', 'scanner-guard:')
        );

        expect($event)->toBeNull();
    } finally {
        putenv('SCANNER_GUARD_DRIVER');
        unset($_ENV['SCANNER_GUARD_DRIVER']);
    }
});
