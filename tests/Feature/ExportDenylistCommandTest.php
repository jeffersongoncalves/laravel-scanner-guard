<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\File;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardBan;
use JeffersonGoncalves\ScannerGuard\ScannerGuard;

afterEach(function () {
    File::deleteDirectory(storage_path('app/scanner-guard'));
});

it('writes active bans as nginx deny lines when the raw ip is still cached', function () {
    $ip = '10.20.20.20';
    app(ScannerGuard::class)->ban($ip, ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);

    $this->artisan('scanner-guard:export-denylist', ['--path' => 'storage/app/scanner-guard/denylist-test.conf'])
        ->assertSuccessful();

    $contents = File::get(storage_path('app/scanner-guard/denylist-test.conf'));
    expect($contents)->toContain("deny {$ip};");
});

it('skips bans whose raw ip is no longer cached, without failing the export', function () {
    $ip = '10.20.20.21';
    app(ScannerGuard::class)->ban($ip, ScannerGuardBan::REASON_SCANNER_PATH, 'wp-admin*', 3);

    Cache::flush();

    $this->artisan('scanner-guard:export-denylist', ['--path' => 'storage/app/scanner-guard/denylist-test2.conf'])
        ->assertSuccessful();

    $contents = File::get(storage_path('app/scanner-guard/denylist-test2.conf'));
    expect($contents)->not->toContain($ip);
});
