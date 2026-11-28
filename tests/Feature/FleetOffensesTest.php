<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardBan;
use JeffersonGoncalves\ScannerGuard\ScannerGuard;

beforeEach(function () {
    config(['scanner-guard.store_details' => true, 'scanner-guard.escalation_lookback_days' => 30]);
});

function fleetBan(string $ip, string $reason, ?int $offense, string $source, int $daysAgo): void
{
    $bannedAt = now()->subDays($daysAgo);

    // Straight to the table: recordForwardedBan() drops a second ban of the same IP within a burst.
    ScannerGuardBan::query()->create([
        'ip_hash' => app(ScannerGuard::class)->hashIp($ip), 'ip' => $ip, 'reason' => $reason, 'matched_value' => 'p', 'hit_count' => 3,
        'banned_at' => $bannedAt, 'expires_at' => $bannedAt->copy()->addDay(), 'offense' => $offense, 'source' => $source,
    ]);
}

it('sends agents each IP highest offense per reason from every server', function () {
    fleetBan('203.0.113.7', 'ssh_bruteforce', 1, 'vps-01', 10);
    fleetBan('203.0.113.7', 'ssh_bruteforce', 2, 'vps-02', 5);
    fleetBan('203.0.113.7', 'ssh_bruteforce', 1, 'vps-03', 2); // latest, lower step
    fleetBan('203.0.113.7', 'web_attack', 1, 'vps-01', 3);
    fleetBan('203.0.113.8', 'ssh_bruteforce', 3, 'vps-01', 40); // past the lookback
    fleetBan('203.0.113.9', 'manual', null, 'vps-01', 1);        // no escalation
    config(['scanner-guard.ip_ignore' => ['203.0.113.10']]);
    fleetBan('203.0.113.10', 'ssh_bruteforce', 1, 'vps-01', 1);

    $offenses = collect(app(ScannerGuard::class)->denylist('vps-04')['offenses'])
        ->mapWithKeys(fn (array $o): array => [$o['ip'].' '.$o['reason'] => [$o['offense'], substr($o['banned_at'], 0, 10)]]);

    expect($offenses->all())->toBe([
        '203.0.113.7 ssh_bruteforce' => [2, now()->subDays(2)->toDateString()],
        '203.0.113.7 web_attack' => [1, now()->subDays(3)->toDateString()],
    ]);
});

it('keeps the history of an IP whose latest row has no raw IP to recover', function () {
    fleetBan('203.0.113.7', 'ssh_bruteforce', 2, 'vps-01', 5);
    fleetBan('203.0.113.7', 'ssh_bruteforce', 1, 'vps-02', 1);
    // The latest row lost its IP (stored before store_details, or a rotated key).
    ScannerGuardBan::query()->latest('banned_at')->first()->forceFill(['ip' => null])->save();

    expect(app(ScannerGuard::class)->denylist('vps-03')['offenses'])->toBe([
        ['ip' => '203.0.113.7', 'reason' => 'ssh_bruteforce', 'offense' => 2, 'banned_at' => now()->subDay()->toIso8601String()],
    ]);
});

it('leaves the offenses out until the add_offense migration ran', function () {
    Schema::table('scanner_guard_bans', fn (Blueprint $table) => $table->dropColumn('offense'));

    try {
        expect(app(ScannerGuard::class)->denylist('vps-01'))->not->toHaveKey('offenses');
    } finally {
        // MySQL and PostgreSQL roll the package migrations back between tests: its down() drops this column.
        if (! Schema::hasColumn('scanner_guard_bans', 'offense')) {
            Schema::table('scanner_guard_bans', fn (Blueprint $table) => $table->unsignedSmallInteger('offense')->nullable());
        }
    }
});

it('leaves the offenses out of a pull without a source', function () {
    expect(app(ScannerGuard::class)->denylist())->not->toHaveKey('offenses');
});
