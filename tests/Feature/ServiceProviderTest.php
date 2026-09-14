<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use JeffersonGoncalves\ScannerGuard\Facades\ScannerGuard as ScannerGuardFacade;
use JeffersonGoncalves\ScannerGuard\ScannerGuard;

it('registers the config file', function () {
    expect(config('scanner-guard.ban_threshold'))->toBe(3);
});

it('registers the scanner_guard_bans migration', function () {
    expect(Schema::hasTable('scanner_guard_bans'))->toBeTrue();
});

it('registers the scanner_guard_ban_daily_stats migration', function () {
    expect(Schema::hasTable('scanner_guard_ban_daily_stats'))->toBeTrue();
});

it('registers the export-denylist command', function () {
    expect(Artisan::all())->toHaveKey('scanner-guard:export-denylist');
});

it('registers the aggregate-and-prune command', function () {
    expect(Artisan::all())->toHaveKey('scanner-guard:aggregate-and-prune');
});

it('registers the scanner-guard middleware alias', function () {
    expect(Route::getMiddleware())->toHaveKey('scanner-guard');
});

it('resolves the facade to the main class', function () {
    expect(ScannerGuardFacade::getFacadeRoot())->toBeInstanceOf(ScannerGuard::class);
});
