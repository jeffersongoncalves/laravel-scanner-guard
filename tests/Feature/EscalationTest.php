<?php

declare(strict_types=1);

use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardBan;
use JeffersonGoncalves\ScannerGuard\ScannerGuard;

beforeEach(function () {
    $this->scannerGuard = app(ScannerGuard::class);

    config(['scanner-guard.escalation' => [86400, 604800, 1209600, 2592000, 7776000]]);
});

function banFor(ScannerGuardBan $ban): int
{
    return (int) $ban->banned_at->diffInSeconds($ban->expires_at);
}

it('escalates each repeat ban one step and repeats the last step', function () {
    foreach ([[1, 86400], [2, 604800], [3, 1209600], [4, 2592000], [5, 7776000], [6, 7776000]] as [$offense, $seconds]) {
        $ban = $this->scannerGuard->ban('1.2.3.4', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);

        expect($ban->offense)->toBe($offense)
            ->and(banFor($ban))->toBe($seconds)
            ->and($ban->fresh()->offense)->toBe($offense);

        $this->travelTo($ban->expires_at->copy()->addSecond());
    }
});

it('ignores prior bans older than the lookback', function () {
    $this->scannerGuard->ban('1.2.3.4', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);
    $this->travel(366)->days();

    $ban = $this->scannerGuard->ban('1.2.3.4', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);

    expect($ban->offense)->toBe(1)->and(banFor($ban))->toBe(86400);
});

it('neither escalates nor counts reasons outside escalation_reasons', function () {
    config(['scanner-guard.ban_duration' => 3600]);

    $asn = $this->scannerGuard->ban('1.2.3.4', ScannerGuardBan::REASON_ASN, 'AS16276', 1);
    $this->travel(2)->hours();
    $ban = $this->scannerGuard->ban('1.2.3.4', ScannerGuardBan::REASON_NOT_FOUND_FLOOD, '404', 20);

    expect($asn->offense)->toBeNull()
        ->and(banFor($asn))->toBe(3600)
        ->and($ban->offense)->toBe(1);
});

it('keeps the fixed ban_duration when escalation is empty', function () {
    config(['scanner-guard.escalation' => [], 'scanner-guard.ban_duration' => 3600]);

    $first = $this->scannerGuard->ban('1.2.3.4', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);
    $this->travel(2)->hours();
    $second = $this->scannerGuard->ban('1.2.3.4', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);

    expect($first->offense)->toBeNull()
        ->and($second->offense)->toBeNull()
        ->and(banFor($second))->toBe(3600);
});

it('escalates cache-driver bans through the cache counter', function () {
    config(['scanner-guard.driver' => 'cache']);

    $this->scannerGuard->ban('1.2.3.4', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);
    $this->travel(2)->days();
    $this->scannerGuard->ban('1.2.3.4', ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);
    $this->travel(6)->days();

    // A 1-day ban would have expired; the 2nd offense lasts 7 days.
    expect($this->scannerGuard->isBanned('1.2.3.4'))->toBeTrue();

    $this->travel(2)->days();

    expect($this->scannerGuard->isBanned('1.2.3.4'))->toBeFalse()
        ->and(ScannerGuardBan::query()->count())->toBe(0);
});
