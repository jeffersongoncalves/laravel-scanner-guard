<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardBan;
use JeffersonGoncalves\ScannerGuard\ScannerGuard;

function statsRow(string $date): ?object
{
    return DB::table('scanner_guard_ban_daily_stats')->where('date', $date)->first();
}

/**
 * Inserts a ban row directly, bypassing the ban-time counter — simulates
 * rows created before that counter existed.
 */
function rawBan(array $attributes): ScannerGuardBan
{
    return ScannerGuardBan::query()->create($attributes + [
        'ip_hash' => 'hash-'.uniqid(),
        'reason' => ScannerGuardBan::REASON_SCANNER_PATH,
        'matched_value' => 'wp-admin*',
        'hit_count' => 3,
    ]);
}

it('counts a ban on its banned_at day at ban time', function () {
    app(ScannerGuard::class)->ban('1.2.3.4', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);
    app(ScannerGuard::class)->ban('5.6.7.8', ScannerGuardBan::REASON_ASN, 'AS16276', 1);

    $row = statsRow(now()->toDateString());

    expect((int) $row->bans_count)->toBe(2)
        ->and((int) $row->hits_total)->toBe(4)
        ->and(json_decode((string) $row->reason_stats, true))->toBe([ScannerGuardBan::REASON_SCANNER_PATH => 1, ScannerGuardBan::REASON_ASN => 1])
        ->and(json_decode((string) $row->top_matched_values, true))->toBe(['wp-admin*' => 3, 'AS16276' => 1])
        ->and(statsRow(now()->addDay()->toDateString()))->toBeNull();
});

it('keeps the daily count after the ban is purged or unbanned the same day', function () {
    $guard = app(ScannerGuard::class);
    $guard->ban('1.1.1.1', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3)->delete();
    $guard->ban('2.2.2.2', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);
    $guard->ban('3.3.3.3', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);
    ScannerGuardBan::query()->delete();

    $this->travel(1)->days();
    $this->artisan('scanner-guard:aggregate-and-prune')->assertExitCode(0);

    expect((int) statsRow(now()->subDay()->toDateString())->bans_count)->toBe(3);
});

it('attributes reconciled bans to their banned_at day, not their expires_at day', function () {
    rawBan(['banned_at' => now()->subDays(2), 'expires_at' => now()->subDay()]);

    $this->artisan('scanner-guard:aggregate-and-prune')->assertExitCode(0);

    expect((int) statsRow(now()->subDays(2)->toDateString())->bans_count)->toBe(1)
        ->and((int) statsRow(now()->subDay()->toDateString())->bans_count)->toBe(0);
});

it('backfills every day the scheduler skipped', function () {
    rawBan(['banned_at' => now()->subDays(3), 'expires_at' => now()->addDay()]);
    rawBan(['banned_at' => now()->subDays(2), 'expires_at' => now()->addDay(), 'hit_count' => 5]);

    $this->artisan('scanner-guard:aggregate-and-prune')->assertExitCode(0);

    expect((int) statsRow(now()->subDays(3)->toDateString())->bans_count)->toBe(1)
        ->and((int) statsRow(now()->subDays(2)->toDateString())->hits_total)->toBe(5);
});

it('never lowers a counter when reconciling', function () {
    $this->travel(-1)->days();
    app(ScannerGuard::class)->ban('1.1.1.1', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);
    app(ScannerGuard::class)->ban('2.2.2.2', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);
    $this->travelBack();

    ScannerGuardBan::query()->first()->delete();

    $this->artisan('scanner-guard:aggregate-and-prune')->assertExitCode(0);

    $row = statsRow(now()->subDay()->toDateString());
    expect((int) $row->bans_count)->toBe(2)
        ->and(json_decode((string) $row->top_matched_values, true))->toBe(['wp-admin*' => 6]);
});

it('purges expired bans only after their day is recorded', function () {
    $this->travelTo(today()->setTime(12, 0));

    $recorded = rawBan(['banned_at' => now()->subDays(2), 'expires_at' => now()->subDay()]);
    $today = rawBan(['banned_at' => now()->subMinutes(10), 'expires_at' => now()->subMinute()]);
    $active = rawBan(['banned_at' => now()->subDay(), 'expires_at' => now()->addHour()]);

    $this->artisan('scanner-guard:aggregate-and-prune')->assertExitCode(0);

    expect(ScannerGuardBan::query()->find($recorded->id))->toBeNull()
        ->and((int) statsRow(now()->subDays(2)->toDateString())->bans_count)->toBe(1)
        ->and(ScannerGuardBan::query()->find($today->id))->not->toBeNull()
        ->and(ScannerGuardBan::query()->find($active->id))->not->toBeNull();
});

it('keeps expired bans when purging is disabled, pruning only past retention', function () {
    config(['scanner-guard.purge_expired_after_days' => null, 'scanner-guard.retention_days' => 30]);

    $recent = rawBan(['banned_at' => now()->subDays(2), 'expires_at' => now()->subDay()]);
    rawBan(['banned_at' => now()->subDays(90), 'expires_at' => now()->subDays(89)]);

    $this->artisan('scanner-guard:aggregate-and-prune')->assertExitCode(0);

    expect(ScannerGuardBan::query()->pluck('id')->all())->toBe([$recent->id])
        ->and((int) statsRow(now()->subDays(90)->toDateString())->bans_count)->toBe(1);
});

it('rebuilds stats keyed by the old expiry day with --rebuild', function () {
    DB::table('scanner_guard_ban_daily_stats')->insert([
        'date' => now()->subDay()->toDateString(),
        'bans_count' => 7,
        'hits_total' => 21,
    ]);
    rawBan(['banned_at' => now()->subDays(2), 'expires_at' => now()->subDay()]);

    $this->artisan('scanner-guard:aggregate-and-prune', ['--rebuild' => true])->assertExitCode(0);

    expect((int) statsRow(now()->subDays(2)->toDateString())->bans_count)->toBe(1)
        ->and((int) statsRow(now()->subDay()->toDateString())->bans_count)->toBe(0);
});

it('reconciles from --date', function () {
    $date = now()->subDays(5);
    rawBan(['banned_at' => $date, 'expires_at' => $date, 'hit_count' => 4]);

    $this->artisan('scanner-guard:aggregate-and-prune', ['--date' => $date->toDateString()])
        ->assertExitCode(0);

    expect((int) statsRow($date->toDateString())->hits_total)->toBe(4);
});

it('reads a zero-filled daily history with today live', function () {
    app(ScannerGuard::class)->ban('1.2.3.4', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);

    $stats = app(ScannerGuard::class)->dailyStats(3);

    expect($stats)->toHaveCount(3)
        ->and($stats->pluck('date')->all())->toBe([
            now()->subDays(2)->toDateString(),
            now()->subDay()->toDateString(),
            now()->toDateString(),
        ])
        ->and($stats->pluck('bans_count')->all())->toBe([0, 0, 1])
        ->and($stats->last()['reason_stats'])->toBe([ScannerGuardBan::REASON_SCANNER_PATH => 1]);
});
