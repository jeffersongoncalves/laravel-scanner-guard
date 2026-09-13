<?php

declare(strict_types=1);

namespace JeffersonGoncalves\ScannerGuard;

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Support\Facades\Route;
use JeffersonGoncalves\ScannerGuard\Console\Commands\ExportDenylistCommand;
use JeffersonGoncalves\ScannerGuard\Http\Middleware\BlockScannerRequests;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

class ScannerGuardServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        $package
            ->name('laravel-scanner-guard')
            ->hasConfigFile('scanner-guard')
            ->hasMigration('create_scanner_guard_bans_table')
            ->hasCommand(ExportDenylistCommand::class);
    }

    public function packageRegistered(): void
    {
        $this->app->singleton(ScannerGuard::class);
        $this->app->singleton('laravel-scanner-guard', fn ($app) => $app->make(ScannerGuard::class));
    }

    public function packageBooted(): void
    {
        // Registers the alias so the middleware is wirable by name. This does
        // NOT apply it globally — attach `scanner-guard` to a route/group
        // yourself (see the README).
        Route::aliasMiddleware('scanner-guard', BlockScannerRequests::class);

        if (! config('scanner-guard.sync_to_nginx', false)) {
            return;
        }

        $this->app->booted(function (): void {
            $this->app->make(Schedule::class)
                ->command(ExportDenylistCommand::class)
                ->daily();
        });
    }
}
