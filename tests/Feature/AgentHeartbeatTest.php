<?php

declare(strict_types=1);

use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardAgent;
use JeffersonGoncalves\ScannerGuard\ScannerGuard;
use JeffersonGoncalves\ScannerGuard\ScannerGuardServiceProvider;

beforeEach(function () {
    config(['scanner-guard.http.server.enabled' => true, 'scanner-guard.http.secret' => 'shared-secret']);
    (new ScannerGuardServiceProvider(app()))->packageBooted();
});

function postHeartbeat(array $payload, string $secret = 'shared-secret', ?int $timestamp = null)
{
    $timestamp = (string) ($timestamp ?? now()->timestamp);
    $body = json_encode($payload, JSON_THROW_ON_ERROR);

    return test()->call('POST', '/scanner-guard/bans/heartbeat', [], [], [], [
        'CONTENT_TYPE' => 'application/json',
        'HTTP_ACCEPT' => 'application/json',
        'HTTP_X_TIMESTAMP' => $timestamp,
        'HTTP_X_SIGNATURE' => app(ScannerGuard::class)->sign($timestamp, $body, $secret),
    ], $body);
}

function heartbeat(array $overrides = []): array
{
    return array_merge([
        'source' => 'vps-01',
        'version' => '1.0.0',
        'rules' => ['ssh_bruteforce', 'nginx_scanner'],
        'active_bans' => 3,
        'started_at' => '2026-11-22T10:00:00Z',
    ], $overrides);
}

it('records a signed heartbeat, one row per source', function () {
    postHeartbeat(heartbeat())->assertNoContent();

    $this->travel(2)->minutes();
    postHeartbeat(heartbeat(['version' => '1.1.0', 'active_bans' => 5]))->assertNoContent();

    expect(ScannerGuardAgent::query()->count())->toBe(1);

    $agent = ScannerGuardAgent::query()->firstOrFail();
    expect($agent->source)->toBe('vps-01')
        ->and($agent->version)->toBe('1.1.0')
        ->and($agent->rules)->toBe(['ssh_bruteforce', 'nginx_scanner'])
        ->and($agent->active_bans)->toBe(5)
        ->and($agent->started_at?->toIso8601String())->toBe('2026-11-22T10:00:00+00:00')
        ->and($agent->last_seen_at->timestamp)->toBe(now()->timestamp)
        ->and($agent->isOnline())->toBeTrue();
});

it('records the OS and addresses, and keeps them when an older agent leaves them out', function () {
    postHeartbeat(heartbeat(['os' => 'Ubuntu 22.04.5 LTS', 'addresses' => ['10.2.0.251', '2001:db8::1']]))->assertNoContent();

    $agent = ScannerGuardAgent::query()->sole();
    expect($agent->os)->toBe('Ubuntu 22.04.5 LTS')
        ->and($agent->addresses)->toBe(['10.2.0.251', '2001:db8::1']);

    $this->travel(1)->minutes();
    postHeartbeat(heartbeat())->assertNoContent();

    expect($agent->refresh()->os)->toBe('Ubuntu 22.04.5 LTS')
        ->and($agent->addresses)->toBe(['10.2.0.251', '2001:db8::1']);

    postHeartbeat(heartbeat(['addresses' => ['not-an-ip']]))->assertUnprocessable();
    postHeartbeat(heartbeat(['os' => str_repeat('x', 101)]))->assertUnprocessable();
});

it('rejects bad signatures, stale timestamps, replays and other sources secrets', function () {
    postHeartbeat(heartbeat(), 'wrong')->assertForbidden();
    postHeartbeat(heartbeat(), timestamp: now()->subMinutes(10)->timestamp)->assertForbidden();

    $timestamp = now()->timestamp;
    postHeartbeat(heartbeat(), timestamp: $timestamp)->assertNoContent();
    postHeartbeat(heartbeat(), timestamp: $timestamp)->assertStatus(409);

    config(['scanner-guard.http.secrets' => ['vps-01' => 'vps-secret']]);
    postHeartbeat(heartbeat(['active_bans' => 9]))->assertForbidden();
    postHeartbeat(heartbeat(['active_bans' => 9]), 'vps-secret')->assertNoContent();

    expect(ScannerGuardAgent::query()->sole()->active_bans)->toBe(9);
});

it('never lets another casing of a source overwrite its row', function () {
    config(['scanner-guard.http.secrets' => ['shop' => 'shop-secret']]);

    postHeartbeat(heartbeat(['source' => 'shop', 'active_bans' => 1]), 'shop-secret')->assertNoContent();
    // "SHOP" is not listed, so the shared secret is accepted for it.
    postHeartbeat(heartbeat(['source' => 'SHOP', 'active_bans' => 99]))->assertNoContent();

    expect(ScannerGuardAgent::query()->count())->toBe(2)
        ->and(ScannerGuardAgent::query()->where('source', 'shop')->sole()->active_bans)->toBe(1);
});

it('validates the payload', function () {
    postHeartbeat(heartbeat(['source' => null]))->assertUnprocessable(); // signed with the shared secret, still needs a source
    postHeartbeat(heartbeat(['rules' => [str_repeat('x', 31)]]))->assertUnprocessable();
    postHeartbeat(heartbeat(['active_bans' => -1]))->assertUnprocessable();

    expect(ScannerGuardAgent::query()->count())->toBe(0);
});

it('tells online agents from offline ones', function () {
    postHeartbeat(heartbeat(['source' => 'old']))->assertNoContent();
    $this->travel(ScannerGuardAgent::STALE_AFTER + 1)->seconds();
    postHeartbeat(heartbeat(['source' => 'fresh']))->assertNoContent();

    expect(ScannerGuardAgent::query()->online()->pluck('source')->all())->toBe(['fresh'])
        ->and(ScannerGuardAgent::query()->offline()->pluck('source')->all())->toBe(['old'])
        ->and(ScannerGuardAgent::query()->where('source', 'old')->sole()->isOnline())->toBeFalse();
});

it('is not routed when the server is disabled', function () {
    app('router')->getRoutes()->refreshNameLookups();
    expect(app('router')->getRoutes()->getByName('scanner-guard.agents.heartbeat'))->not->toBeNull();

    $this->refreshApplication(); // server.enabled defaults to false

    expect(app('router')->getRoutes()->getByName('scanner-guard.agents.heartbeat'))->toBeNull();
});
