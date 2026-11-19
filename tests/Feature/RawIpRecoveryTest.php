<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Route;
use JeffersonGoncalves\ScannerGuard\Jobs\SyncDenylist;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardBan;
use JeffersonGoncalves\ScannerGuard\ScannerGuard;
use JeffersonGoncalves\ScannerGuard\Tests\Fixtures\RecordingSink;

beforeEach(function () {
    Route::middleware('scanner-guard')->get('/hello', fn () => 'ok');
    $this->guard = app(ScannerGuard::class);
});

/**
 * A ban whose raw IP was lost, e.g. to a cache:clear on deploy.
 */
function banAndLoseRawIp(string $ip): ScannerGuardBan
{
    $ban = app(ScannerGuard::class)->ban($ip, ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);
    app(ScannerGuard::class)->cache()->forget('scanner-guard:raw-ip:'.app(ScannerGuard::class)->hashIp($ip));

    return $ban;
}

it('re-caches a lost raw ip when the banned ip comes back, until the ban expires', function () {
    $ban = banAndLoseRawIp('203.0.113.50');
    expect($this->guard->rawIpFor($ban->ip_hash))->toBeNull();

    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.50'])->get('/hello')->assertNotFound();

    expect($this->guard->rawIpFor($ban->ip_hash))->toBe('203.0.113.50');

    $this->travelTo($ban->expires_at->copy()->addSecond());
    expect($this->guard->rawIpFor($ban->ip_hash))->toBeNull();
});

it('queues a denylist sync once the raw ip is back, so sinks get the ban again', function () {
    config(['scanner-guard.sinks' => [RecordingSink::class]]);
    banAndLoseRawIp('203.0.113.51');
    Queue::fake();

    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.51'])->get('/hello')->assertNotFound();

    Queue::assertPushed(SyncDenylist::class);
});

it('looks the ban up at most once a minute per ip', function () {
    banAndLoseRawIp('203.0.113.52');
    // Row gone but the cached ban still answers: nothing to recover from.
    ScannerGuardBan::query()->delete();
    $queries = 0;
    DB::listen(function ($query) use (&$queries) {
        if (str_contains($query->sql, 'scanner_guard_bans')) {
            $queries++;
        }
    });

    foreach (range(1, 5) as $ignored) {
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.52'])->get('/hello')->assertNotFound();
    }

    expect($queries)->toBe(1);

    $this->travel(61)->seconds();
    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.52'])->get('/hello');

    expect($queries)->toBe(2);
});

it('leaves a cached raw ip alone and skips the lookup', function () {
    $ban = $this->guard->ban('203.0.113.53', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);
    $queries = 0;
    DB::listen(function ($query) use (&$queries) {
        if (str_contains($query->sql, 'scanner_guard_bans')) {
            $queries++;
        }
    });

    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.53'])->get('/hello')->assertNotFound();

    expect($queries)->toBe(0)
        ->and($this->guard->rawIpFor($ban->ip_hash))->toBe('203.0.113.53');
});

it('does nothing with a driver other than database', function () {
    config(['scanner-guard.driver' => 'cache']);
    $this->guard->ban('203.0.113.54', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);
    $hash = $this->guard->hashIp('203.0.113.54');
    $this->guard->cache()->forget("scanner-guard:raw-ip:{$hash}");

    $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.54'])->get('/hello')->assertNotFound();

    expect($this->guard->rawIpFor($hash))->toBeNull();
});
