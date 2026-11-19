<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Queue;
use JeffersonGoncalves\ScannerGuard\Contracts\DenylistSink;
use JeffersonGoncalves\ScannerGuard\Jobs\SyncDenylist;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardBan;
use JeffersonGoncalves\ScannerGuard\ScannerGuard;
use JeffersonGoncalves\ScannerGuard\Tests\Fixtures\RecordingSink;

beforeEach(function () {
    RecordingSink::reset();
});

/**
 * Sinks on, but bans don't queue a sync, so each test drives the command itself.
 */
function withRecordingSink(): void
{
    config(['scanner-guard.sinks' => [RecordingSink::class], 'scanner-guard.sync_on_ban' => false]);
}

it('passes active bans to every sink when the raw ip is still cached', function () {
    withRecordingSink();
    $ban = app(ScannerGuard::class)->ban('10.20.20.20', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);

    $this->artisan('scanner-guard:sync-denylist')->assertSuccessful();

    expect(RecordingSink::last())->toBe([
        ['ip' => '10.20.20.20', 'reason' => 'scanner_path', 'expires_at' => $ban->expires_at->toIso8601String()],
    ]);
});

it('skips bans whose raw ip is no longer cached', function () {
    withRecordingSink();
    app(ScannerGuard::class)->ban('10.20.20.21', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);

    Cache::flush();

    $this->artisan('scanner-guard:sync-denylist')->assertSuccessful();

    expect(RecordingSink::last())->toBe([]);
});

it('skips when no sinks are configured', function () {
    $this->artisan('scanner-guard:sync-denylist')->expectsOutputToContain('no sinks configured')->assertSuccessful();
});

it('releases the sync lock so the next sync can run', function () {
    withRecordingSink();

    $this->artisan('scanner-guard:sync-denylist')->assertSuccessful();

    expect(app(ScannerGuard::class)->cache()->getStore()->lock('scanner-guard:sync-denylist')->get())->toBeTrue();
});

it('passes valid ip_blocklist entries as static and skips invalid ones', function () {
    withRecordingSink();
    Log::spy();
    config()->set('scanner-guard.ip_blocklist', ['185.177.72.69', '185.177.72.0/24', '2001:db8::/32', 'not-an-ip', '10.0.0.0/33', '1.2.3.4; allow all']);

    $this->artisan('scanner-guard:sync-denylist')->assertSuccessful();

    expect(array_column(RecordingSink::last(), 'ip'))->toBe(['185.177.72.69', '185.177.72.0/24', '2001:db8::/32'])
        ->and(array_unique(array_column(RecordingSink::last(), 'reason')))->toBe(['static'])
        ->and(array_unique(array_column(RecordingSink::last(), 'expires_at')))->toBe([null]);
    Log::shouldHaveReceived('warning')->with('scanner-guard: skipped invalid ip_blocklist entry', Mockery::any())->times(3);
});

it('passes one entry per ip, keeping the latest expiry of escalated bans', function () {
    withRecordingSink();
    config(['scanner-guard.escalation' => [86400, 604800]]);
    $guard = app(ScannerGuard::class);
    $guard->ban('10.20.20.30', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);
    $this->travel(2)->minutes(); // past the burst guard
    $guard->ban('10.20.20.30', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);

    expect(ScannerGuardBan::query()->active()->count())->toBe(2);

    $this->artisan('scanner-guard:sync-denylist')->assertSuccessful();

    expect(RecordingSink::last())->toHaveCount(1)
        ->and(RecordingSink::last()[0]['expires_at'])->toBe(ScannerGuardBan::query()->orderByDesc('expires_at')->first()->expires_at->toIso8601String());
});

it('passes only the static entry for an ip that is also banned', function () {
    withRecordingSink();
    config()->set('scanner-guard.ip_blocklist', ['10.20.20.31']);
    app(ScannerGuard::class)->ban('10.20.20.31', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);

    $this->artisan('scanner-guard:sync-denylist')->assertSuccessful();

    expect(RecordingSink::last())->toBe([['ip' => '10.20.20.31', 'reason' => 'static', 'expires_at' => null]]);
});

it('logs a failing sink, keeps running the others and exits with failure', function () {
    Log::spy();
    $failing = new class implements DenylistSink
    {
        public function sync(array $entries): void
        {
            throw new RuntimeException('cloudflare is down');
        }
    };
    app()->instance('failing-sink', $failing);
    config(['scanner-guard.sinks' => ['failing-sink', RecordingSink::class]]);

    $this->artisan('scanner-guard:sync-denylist')->assertFailed();

    expect(RecordingSink::$calls)->toHaveCount(1);
    Log::shouldHaveReceived('error')->withArgs(fn (string $message, array $context) => $message === 'scanner-guard: denylist sink failed'
        && $context['exception'] === 'cloudflare is down');
});

it('queues a sync on every ban when sinks are configured', function () {
    Queue::fake();
    config(['scanner-guard.sinks' => [RecordingSink::class]]);

    app(ScannerGuard::class)->ban('10.20.20.24', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);

    Queue::assertPushed(SyncDenylist::class);
});

it('does not queue a sync without sinks or with sync_on_ban off', function () {
    Queue::fake();
    app(ScannerGuard::class)->ban('10.20.20.25', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);

    withRecordingSink();
    app(ScannerGuard::class)->ban('10.20.20.26', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);

    Queue::assertNothingPushed();
});

it('updates the sinks right after a ban on the sync queue', function () {
    config(['scanner-guard.sinks' => [RecordingSink::class]]);

    app(ScannerGuard::class)->ban('10.20.20.27', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);

    expect(array_column(RecordingSink::last(), 'ip'))->toBe(['10.20.20.27']);
});
