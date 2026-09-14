<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardBan;

it('folds yesterdays expired bans into a daily_stats row and prunes old bans', function () {
    config(['scanner-guard.retention_days' => 30]);

    ScannerGuardBan::query()->create([
        'ip_hash' => 'hash-1',
        'reason' => ScannerGuardBan::REASON_SCANNER_PATH,
        'matched_value' => 'wp-admin*',
        'hit_count' => 3,
        'banned_at' => now()->subDay(),
        'expires_at' => now()->subDay(),
    ]);

    ScannerGuardBan::query()->create([
        'ip_hash' => 'hash-2',
        'reason' => ScannerGuardBan::REASON_ASN,
        'matched_value' => 'AS16276',
        'hit_count' => 5,
        'banned_at' => now()->subDays(90),
        'expires_at' => now()->subDays(90),
    ]);

    $this->artisan('scanner-guard:aggregate-and-prune')->assertExitCode(0);

    $row = DB::table('scanner_guard_ban_daily_stats')
        ->where('date', now()->subDay()->toDateString())
        ->first();

    expect($row)->not->toBeNull()
        ->and((int) $row->bans_count)->toBe(1)
        ->and((int) $row->hits_total)->toBe(3)
        ->and(json_decode((string) $row->reason_stats, true))->toBe([ScannerGuardBan::REASON_SCANNER_PATH => 1])
        ->and(json_decode((string) $row->top_matched_values, true))->toBe(['wp-admin*' => 3])
        ->and(ScannerGuardBan::query()->count())->toBe(1);
});

it('accepts a --date option to backfill a specific day', function () {
    $date = now()->subDays(5);

    ScannerGuardBan::query()->create([
        'ip_hash' => 'hash-3',
        'reason' => ScannerGuardBan::REASON_SCANNER_PATH,
        'matched_value' => 'xmlrpc.php',
        'hit_count' => 4,
        'banned_at' => $date,
        'expires_at' => $date,
    ]);

    $this->artisan('scanner-guard:aggregate-and-prune', ['--date' => $date->toDateString()])
        ->assertExitCode(0);

    $row = DB::table('scanner_guard_ban_daily_stats')->where('date', $date->toDateString())->first();

    expect($row)->not->toBeNull()
        ->and((int) $row->bans_count)->toBe(1)
        ->and((int) $row->hits_total)->toBe(4);
});

it('never aggregates or prunes still-active bans', function () {
    $ban = ScannerGuardBan::query()->create([
        'ip_hash' => 'hash-4',
        'reason' => ScannerGuardBan::REASON_SCANNER_PATH,
        'matched_value' => 'wp-login*',
        'hit_count' => 3,
        'banned_at' => now(),
        'expires_at' => now()->addDay(),
    ]);

    $this->artisan('scanner-guard:aggregate-and-prune')->assertExitCode(0);

    expect(ScannerGuardBan::query()->find($ban->id))->not->toBeNull();

    $row = DB::table('scanner_guard_ban_daily_stats')->where('date', now()->toDateString())->first();
    expect($row)->toBeNull();
});
