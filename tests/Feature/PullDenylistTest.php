<?php

declare(strict_types=1);

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardBan;
use JeffersonGoncalves\ScannerGuard\ScannerGuard;
use JeffersonGoncalves\ScannerGuard\ScannerGuardServiceProvider;
use JeffersonGoncalves\ScannerGuard\Tests\Fixtures\RecordingSink;

beforeEach(function () {
    $this->scannerGuard = app(ScannerGuard::class);

    config([
        'scanner-guard.http.url' => 'https://central.test/scanner-guard/bans',
        'scanner-guard.http.secret' => 'shared-secret',
    ]);
});

function getDenylist(string $source, string $secret, ?int $timestamp = null)
{
    $timestamp = (string) ($timestamp ?? now()->timestamp);

    return test()->getJson('/scanner-guard/bans', [
        'X-Source' => $source,
        'X-Timestamp' => $timestamp,
        'X-Signature' => app(ScannerGuard::class)->sign($timestamp, $source, $secret),
    ]);
}

/**
 * @return array<string, mixed>
 */
function centralDenylist(array $bans, array $ipBlocklist = [], array $patterns = []): array
{
    return ['bans' => $bans, 'ip_blocklist' => $ipBlocklist, 'user_agent_patterns' => $patterns];
}

/**
 * One fake for the whole test: a later Http::fake() would not replace an earlier stub.
 */
function fakeCentral(array ...$responses): void
{
    $sequence = Http::sequence();

    foreach ($responses as $response) {
        $sequence->push($response['body'] ?? $response, $response['status'] ?? 200);
    }

    Http::fake(['central.test/*' => $sequence]);
}

function activeBan(string $ip): array
{
    return ['ip' => $ip, 'reason' => 'scanner_path', 'expires_at' => now()->addDay()->toIso8601String()];
}

it('serves active bans and static lists to a signed satellite', function () {
    config([
        'scanner-guard.http.server.enabled' => true,
        'scanner-guard.ip_blocklist' => ['185.177.72.0/24'],
        'scanner-guard.user_agent_blocklist.patterns' => ['zgrab*'],
    ]);
    (new ScannerGuardServiceProvider(app()))->packageBooted();

    $this->scannerGuard->ban('198.51.100.7', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);

    getDenylist('shop', 'shared-secret')
        ->assertOk()
        ->assertJsonPath('bans.0.ip', '198.51.100.7')
        ->assertJsonPath('bans.0.reason', ScannerGuardBan::REASON_SCANNER_PATH)
        ->assertJsonPath('ip_blocklist', ['185.177.72.0/24'])
        ->assertJsonPath('user_agent_patterns', ['zgrab*']);

    getDenylist('shop', 'wrong')->assertForbidden();
    getDenylist('shop', 'shared-secret', now()->subMinutes(10)->timestamp)->assertForbidden();

    config(['scanner-guard.http.secrets' => ['shop' => 'shop-secret']]);
    getDenylist('shop', 'shared-secret')->assertForbidden();
    getDenylist('shop', 'shop-secret')->assertOk();
});

it('pulls central bans and lists into a satellite, signed with its source', function () {
    config(['scanner-guard.driver' => 'http', 'scanner-guard.http.source' => 'shop']);
    fakeCentral(centralDenylist([activeBan('198.51.100.7')], ['185.177.72.0/24'], ['zgrab*']));

    $this->artisan('scanner-guard:pull-denylist')->assertSuccessful();

    expect($this->scannerGuard->isBanned('198.51.100.7'))->toBeTrue();
    expect($this->scannerGuard->isIpBlocked('185.177.72.69'))->toBeTrue();
    expect($this->scannerGuard->matchUserAgent('zgrab/0.x'))->toBe('zgrab*');

    Http::assertSent(fn (Request $request): bool => $request->method() === 'GET'
        && $request->header('X-Source')[0] === 'shop'
        && $request->header('X-Signature')[0] === $this->scannerGuard->sign($request->header('X-Timestamp')[0], 'shop'));
});

it('lifts bans the central app no longer lists, but keeps local ones not pulled yet', function () {
    config(['scanner-guard.driver' => 'http']);
    $this->withoutDefer();

    // pull, forwarded local ban, pull again without the first ban
    fakeCentral(centralDenylist([activeBan('198.51.100.7')]), ['body' => '', 'status' => 201], centralDenylist([]));

    $this->artisan('scanner-guard:pull-denylist')->assertSuccessful();
    expect($this->scannerGuard->isBanned('198.51.100.7'))->toBeTrue();

    $this->scannerGuard->ban('10.30.0.1', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);

    $this->artisan('scanner-guard:pull-denylist')->assertSuccessful();

    expect($this->scannerGuard->isBanned('198.51.100.7'))->toBeFalse();
    expect($this->scannerGuard->isBanned('10.30.0.1'))->toBeTrue();
});

it('skips invalid and expired pulled entries', function () {
    config(['scanner-guard.driver' => 'http']);
    fakeCentral(centralDenylist([
        activeBan('not-an-ip'),
        ['ip' => '198.51.100.8', 'reason' => 'x', 'expires_at' => now()->subMinute()->toIso8601String()],
        ['ip' => '198.51.100.9', 'reason' => 'x', 'expires_at' => 'garbage'],
        'not-an-array',
    ]));

    $this->artisan('scanner-guard:pull-denylist')->assertSuccessful();

    expect($this->scannerGuard->pulledBans())->toBe([]);
    expect($this->scannerGuard->isBanned('198.51.100.8'))->toBeFalse();
});

it('keeps the last pulled list when the central app is unreachable', function () {
    config(['scanner-guard.driver' => 'http']);
    fakeCentral(centralDenylist([activeBan('198.51.100.7')], ['185.177.72.69']), ['body' => '', 'status' => 500]);

    $this->artisan('scanner-guard:pull-denylist')->assertSuccessful();
    $this->artisan('scanner-guard:pull-denylist')->assertFailed();

    expect($this->scannerGuard->isBanned('198.51.100.7'))->toBeTrue();
    expect($this->scannerGuard->isIpBlocked('185.177.72.69'))->toBeTrue();
});

it('syncs the satellite sinks from the pull when sinks are configured', function () {
    RecordingSink::reset();
    config(['scanner-guard.driver' => 'http', 'scanner-guard.sinks' => [RecordingSink::class]]);
    $ban = activeBan('198.51.100.7');
    fakeCentral(centralDenylist([$ban], ['185.177.72.0/24']));

    $this->artisan('scanner-guard:pull-denylist')->assertSuccessful();

    expect(RecordingSink::last())->toBe([
        ['ip' => '185.177.72.0/24', 'reason' => 'static', 'expires_at' => null],
        ['ip' => '198.51.100.7', 'reason' => 'scanner_path', 'expires_at' => $ban['expires_at']],
    ]);
});

it('ignores pulled lists with a driver other than http', function () {
    config(['scanner-guard.driver' => 'http']);
    fakeCentral(centralDenylist([], ['185.177.72.69']));
    $this->artisan('scanner-guard:pull-denylist')->assertSuccessful();

    config(['scanner-guard.driver' => 'cache']);

    expect($this->scannerGuard->isIpBlocked('185.177.72.69'))->toBeFalse();
    $this->artisan('scanner-guard:pull-denylist')->expectsOutputToContain('Skipped')->assertSuccessful();
});

it('schedules the pull every minute only on http satellites with pull on', function () {
    $pullEvent = fn () => collect(app(Schedule::class)->events())->first(
        fn ($event) => str_contains($event->command ?? '', 'scanner-guard:pull-denylist')
    );

    expect($pullEvent())->toBeNull();

    putenv('SCANNER_GUARD_DRIVER=http');
    putenv('SCANNER_GUARD_HTTP_PULL=true');

    try {
        $this->refreshApplication();

        expect($pullEvent()?->expression)->toBe('* * * * *');
    } finally {
        putenv('SCANNER_GUARD_DRIVER');
        putenv('SCANNER_GUARD_HTTP_PULL');
    }
});
