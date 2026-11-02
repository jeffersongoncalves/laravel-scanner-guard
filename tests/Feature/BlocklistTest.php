<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Route;
use JeffersonGoncalves\ScannerGuard\Jobs\ExportDenylist;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardBan;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardBlocklistEntry;
use JeffersonGoncalves\ScannerGuard\ScannerGuard;

beforeEach(function () {
    Route::get('/hello', fn () => 'ok')->middleware('scanner-guard');
});

function blockEntry(string $type, string $value): ScannerGuardBlocklistEntry
{
    return ScannerGuardBlocklistEntry::query()->create(['type' => $type, 'value' => $value]);
}

it('blocks ips and cidr ranges stored in the database, next to the config ones', function (string $ip) {
    config(['scanner-guard.ip_blocklist' => ['185.177.72.69']]);
    blockEntry(ScannerGuardBlocklistEntry::TYPE_IP, '10.9.0.0/16');
    blockEntry(ScannerGuardBlocklistEntry::TYPE_IP, '2001:db8::1');

    $this->withServerVariables(['REMOTE_ADDR' => $ip])->get('/hello')->assertNotFound();
    $this->withServerVariables(['REMOTE_ADDR' => '10.10.0.1'])->get('/hello')->assertOk();

    expect(ScannerGuardBan::query()->count())->toBe(0);
})->with(['185.177.72.69', '10.9.4.2', '2001:db8::1']);

it('matches user agent patterns stored in the database, next to the config ones', function () {
    config(['scanner-guard.user_agent_blocklist.patterns' => ['zgrab*']]);
    blockEntry(ScannerGuardBlocklistEntry::TYPE_USER_AGENT, '*masscan*');

    $guard = app(ScannerGuard::class);

    expect($guard->matchUserAgent('MASSCAN/1.3'))->toBe('*masscan*')
        ->and($guard->matchUserAgent('zgrab/0.x'))->toBe('zgrab*')
        ->and($guard->matchUserAgent('Mozilla/5.0'))->toBeNull();
});

it('applies an added or removed entry on the next call, with no re-boot', function () {
    $guard = app(ScannerGuard::class);
    expect($guard->isIpBlocked('10.30.0.1'))->toBeFalse();

    $entry = blockEntry(ScannerGuardBlocklistEntry::TYPE_IP, '10.30.0.1');
    expect($guard->isIpBlocked('10.30.0.1'))->toBeTrue();

    $entry->delete();
    expect($guard->isIpBlocked('10.30.0.1'))->toBeFalse();
});

it('reads the database list from cache, not with a query per check', function () {
    blockEntry(ScannerGuardBlocklistEntry::TYPE_IP, '10.30.0.2');
    $guard = app(ScannerGuard::class);
    $guard->ipBlocklist();

    DB::enableQueryLog();
    $guard->ipBlocklist();
    $guard->userAgentPatterns();

    expect(DB::getQueryLog())->toBe([]);
});

it('ignores the database list with a driver other than database', function () {
    blockEntry(ScannerGuardBlocklistEntry::TYPE_IP, '10.30.0.3');
    config(['scanner-guard.driver' => 'cache']);

    expect(app(ScannerGuard::class)->isIpBlocked('10.30.0.3'))->toBeFalse();
});

it('falls back to the config lists when the blocklist query fails, e.g. migration not run', function () {
    config(['scanner-guard.ip_blocklist' => ['10.30.0.4']]);

    // A failing query on the test connection would abort its wrapping transaction on PostgreSQL.
    $default = config('database.default');
    config([
        'database.connections.broken' => ['driver' => 'sqlite', 'database' => __DIR__.'/missing.sqlite', 'prefix' => ''],
        'database.default' => 'broken',
    ]);

    try {
        expect(app(ScannerGuard::class)->ipBlocklist())->toBe(['10.30.0.4']);
    } finally {
        config(['database.default' => $default]);
    }
});

it('queues an nginx export on every blocklist change when sync_to_nginx is on', function () {
    Queue::fake();
    config(['scanner-guard.sync_to_nginx' => true]);

    $entry = blockEntry(ScannerGuardBlocklistEntry::TYPE_IP, '10.30.0.5');
    Queue::assertPushed(ExportDenylist::class);

    Cache::flush(); // releases the unique-job lock the faked job never processes
    Queue::fake();
    $entry->delete();
    Queue::assertPushed(ExportDenylist::class);
});

it('keeps an existing blocklist table and its rows when the migration runs again or rolls back', function () {
    blockEntry(ScannerGuardBlocklistEntry::TYPE_IP, '10.30.0.6');

    $migration = include __DIR__.'/../../database/migrations/create_scanner_guard_blocklist_table.php.stub';
    $migration->up();
    $migration->down();

    expect(ScannerGuardBlocklistEntry::query()->pluck('value')->all())->toBe(['10.30.0.6']);
});

it('does not let a read started before a change re-cache the old list', function () {
    $guard = app(ScannerGuard::class);
    $guard->ipBlocklist();
    $oldVersion = $guard->cache()->get('scanner-guard:blocklist-version');

    blockEntry(ScannerGuardBlocklistEntry::TYPE_IP, '10.30.0.10');
    // The in-flight read finishes after the change and writes the rows it saw.
    $guard->cache()->forever("scanner-guard:blocklist:{$oldVersion}", []);

    expect($guard->isIpBlocked('10.30.0.10'))->toBeTrue();
});

it('neither refreshes nor exports a blocklist change that is rolled back', function () {
    Queue::fake();
    config(['scanner-guard.sync_to_nginx' => true]);
    $guard = app(ScannerGuard::class);
    $guard->ipBlocklist();
    $version = $guard->cache()->get('scanner-guard:blocklist-version');

    try {
        DB::transaction(function () {
            blockEntry(ScannerGuardBlocklistEntry::TYPE_IP, '10.30.0.11');

            throw new RuntimeException('rollback');
        });
    } catch (RuntimeException) {
    }

    expect($guard->cache()->get('scanner-guard:blocklist-version'))->toBe($version)
        ->and($guard->isIpBlocked('10.30.0.11'))->toBeFalse();
    Queue::assertNothingPushed();
});

it('exports blocklist changes and unbans even with export_on_ban off', function () {
    Queue::fake();
    config(['scanner-guard.sync_to_nginx' => true, 'scanner-guard.nginx.export_on_ban' => false]);

    app(ScannerGuard::class)->unban(app(ScannerGuard::class)->hashIp('10.30.0.12'));

    Queue::assertPushed(ExportDenylist::class);
});

it('unban() lifts a cached ban at once and returns the deleted row count', function () {
    $guard = app(ScannerGuard::class);
    $guard->ban('10.30.0.7', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);
    expect($guard->isBanned('10.30.0.7'))->toBeTrue();

    expect($guard->unban($guard->hashIp('10.30.0.7')))->toBe(1)
        ->and($guard->isBanned('10.30.0.7'))->toBeFalse()
        ->and($guard->rawIpFor($guard->hashIp('10.30.0.7')))->toBeNull();

    $this->withServerVariables(['REMOTE_ADDR' => '10.30.0.7'])->get('/hello')->assertOk();
});

it('unban() queues an nginx export when sync_to_nginx is on', function () {
    Queue::fake();
    config(['scanner-guard.sync_to_nginx' => true]);

    app(ScannerGuard::class)->unban(app(ScannerGuard::class)->hashIp('10.30.0.8'));

    Queue::assertPushed(ExportDenylist::class);
});

it('never lets a failing export dispatch break a blocklist change or unban()', function () {
    Log::spy();
    config(['scanner-guard.sync_to_nginx' => true, 'queue.default' => 'missing']);
    $guard = app(ScannerGuard::class);

    $entry = blockEntry(ScannerGuardBlocklistEntry::TYPE_IP, '10.30.0.9');
    expect($guard->isIpBlocked('10.30.0.9'))->toBeTrue();

    $entry->delete();
    expect($guard->unban($guard->hashIp('10.30.0.9')))->toBe(0);

    Log::shouldHaveReceived('error')->with('scanner-guard: failed to queue nginx export', Mockery::any())->times(3);
});
