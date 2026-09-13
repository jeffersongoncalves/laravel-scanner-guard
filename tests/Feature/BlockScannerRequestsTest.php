<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Route;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardBan;
use JeffersonGoncalves\ScannerGuard\ScannerGuard;
use JeffersonGoncalves\VisitorFingerprint\Contracts\GeoIpDriver;
use JeffersonGoncalves\VisitorFingerprint\Data\GeoLocation;

beforeEach(function () {
    Route::get('/wp-admin', fn () => 'ok')->middleware('scanner-guard');
    Route::get('/hello', fn () => 'ok')->middleware('scanner-guard');

    config(['scanner-guard.ban_threshold' => 3]);
});

it('passes non-matching paths through untouched', function () {
    $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.1'])->get('/hello')->assertOk();

    expect(ScannerGuardBan::query()->count())->toBe(0);
});

it('counts scanner-path hits and only bans once the threshold is reached', function () {
    $ip = '10.0.0.2';

    $this->withServerVariables(['REMOTE_ADDR' => $ip])->get('/wp-admin')->assertOk();
    $this->withServerVariables(['REMOTE_ADDR' => $ip])->get('/wp-admin')->assertOk();
    expect(ScannerGuardBan::query()->count())->toBe(0);

    $this->withServerVariables(['REMOTE_ADDR' => $ip])->get('/wp-admin')->assertNotFound();

    $ban = ScannerGuardBan::query()->sole();
    expect($ban->reason)->toBe(ScannerGuardBan::REASON_SCANNER_PATH);
    expect($ban->matched_value)->toBe('wp-admin*');
    expect($ban->hit_count)->toBe(3);
});

it('short-circuits an already-banned ip without creating a second ban row', function () {
    $ip = '10.0.0.3';
    app(ScannerGuard::class)->ban($ip, ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);

    $this->withServerVariables(['REMOTE_ADDR' => $ip])->get('/hello')->assertNotFound();

    expect(ScannerGuardBan::query()->count())->toBe(1);
});

it('bans immediately on an asn-blocklist match, without needing a scanner path', function () {
    $ip = '10.0.0.4';

    app()->bind(GeoIpDriver::class, fn () => new class implements GeoIpDriver
    {
        public function resolve(string $ip): GeoLocation
        {
            return new GeoLocation(asn: 'AS16276 OVH SAS');
        }
    });

    config(['scanner-guard.asn_blocklist' => ['AS16276']]);

    $this->withServerVariables(['REMOTE_ADDR' => $ip])->get('/hello')->assertNotFound();

    $ban = ScannerGuardBan::query()->sole();
    expect($ban->reason)->toBe(ScannerGuardBan::REASON_ASN);
    expect($ban->matched_value)->toBe('AS16276 OVH SAS');
});

it('does not resolve the geoip driver at all when the asn blocklist is empty', function () {
    config(['scanner-guard.asn_blocklist' => []]);

    app()->bind(GeoIpDriver::class, function () {
        throw new RuntimeException('GeoIpDriver should not be resolved when asn_blocklist is empty.');
    });

    $this->withServerVariables(['REMOTE_ADDR' => '10.0.0.5'])->get('/hello')->assertOk();
});

it('is a no-op entirely when disabled', function () {
    config(['scanner-guard.enabled' => false]);

    $ip = '10.0.0.6';
    $this->withServerVariables(['REMOTE_ADDR' => $ip])->get('/wp-admin')->assertOk();
    $this->withServerVariables(['REMOTE_ADDR' => $ip])->get('/wp-admin')->assertOk();
    $this->withServerVariables(['REMOTE_ADDR' => $ip])->get('/wp-admin')->assertOk();

    expect(ScannerGuardBan::query()->count())->toBe(0);
});
