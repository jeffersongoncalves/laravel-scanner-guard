<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Cache;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardBan;
use JeffersonGoncalves\ScannerGuard\ScannerGuard;
use JeffersonGoncalves\VisitorFingerprint\Support\IpAnonymizer;

beforeEach(function () {
    $this->scannerGuard = app(ScannerGuard::class);
});

it('matches configured scanner path patterns, case-insensitively, leading slash or not', function () {
    expect($this->scannerGuard->matchScannerPath('wp-admin/setup-config.php'))->toBe('wp-admin*');
    expect($this->scannerGuard->matchScannerPath('/WP-LOGIN.php'))->toBe('wp-login*');
    expect($this->scannerGuard->matchScannerPath('about-us'))->toBeNull();
});

it('hashes ips the same way jeffersongoncalves/laravel-visitor-fingerprint does', function () {
    expect($this->scannerGuard->hashIp('203.0.113.5'))->toBe(IpAnonymizer::hash('203.0.113.5'));
});

it('detects a blocklisted asn in either bare or descriptive form', function () {
    config(['scanner-guard.asn_blocklist' => ['AS16276']]);

    expect($this->scannerGuard->isAsnBlocked('AS16276'))->toBeTrue();
    expect($this->scannerGuard->isAsnBlocked('AS16276 OVH SAS'))->toBeTrue();
    expect($this->scannerGuard->isAsnBlocked('AS12345 Some Other ISP'))->toBeFalse();
    expect($this->scannerGuard->isAsnBlocked(null))->toBeFalse();
});

it('never flags an asn when the blocklist is empty', function () {
    config(['scanner-guard.asn_blocklist' => []]);

    expect($this->scannerGuard->isAsnBlocked('AS16276'))->toBeFalse();
});

it('increments the per-ip hit counter and resets it once banned', function () {
    $ip = '10.10.10.10';

    expect($this->scannerGuard->registerHit($ip))->toBe(1);
    expect($this->scannerGuard->registerHit($ip))->toBe(2);

    $this->scannerGuard->ban($ip, ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 2);

    expect($this->scannerGuard->registerHit($ip))->toBe(1);
});

it('writes a permanent hashed ban row, never the raw ip', function () {
    $ip = '10.10.10.11';

    $ban = $this->scannerGuard->ban($ip, ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);

    expect($ban->ip_hash)->toBe($this->scannerGuard->hashIp($ip));
    expect($ban->ip_hash)->not->toBe($ip);
    expect($this->scannerGuard->isBanned($ip))->toBeTrue();
});

it('recovers an active ban from the database after a cache flush', function () {
    $ip = '10.10.10.12';
    $this->scannerGuard->ban($ip, ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);

    Cache::flush();

    expect($this->scannerGuard->isBanned($ip))->toBeTrue();
});

it('recovers the raw ip cached at ban time, until it is evicted', function () {
    $ip = '10.10.10.13';
    $ban = $this->scannerGuard->ban($ip, ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);

    expect($this->scannerGuard->rawIpFor($ban->ip_hash))->toBe($ip);

    Cache::flush();

    expect($this->scannerGuard->rawIpFor($ban->ip_hash))->toBeNull();
});
