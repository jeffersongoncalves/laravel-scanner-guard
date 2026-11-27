<?php

declare(strict_types=1);

namespace JeffersonGoncalves\ScannerGuard;

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Support\Facades\Route;
use JeffersonGoncalves\ScannerGuard\Console\Commands\AggregateAndPruneCommand;
use JeffersonGoncalves\ScannerGuard\Console\Commands\PullDenylistCommand;
use JeffersonGoncalves\ScannerGuard\Console\Commands\SyncDenylistCommand;
use JeffersonGoncalves\ScannerGuard\Http\Controllers\DenylistController;
use JeffersonGoncalves\ScannerGuard\Http\Controllers\RecordAgentEventController;
use JeffersonGoncalves\ScannerGuard\Http\Controllers\RecordAgentHeartbeatController;
use JeffersonGoncalves\ScannerGuard\Http\Controllers\RecordForwardedBanController;
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
            ->hasMigration('create_scanner_guard_ban_daily_stats_table')
            ->hasMigration('add_offense_to_scanner_guard_bans_table')
            ->hasMigration('create_scanner_guard_blocklist_table')
            ->hasMigration('add_source_to_scanner_guard_bans_table')
            ->hasMigration('create_scanner_guard_agents_table')
            ->hasMigration('add_details_to_scanner_guard_bans_table')
            ->hasMigration('add_evidence_to_scanner_guard_bans_table')
            ->hasMigration('create_scanner_guard_agent_rules_table')
            ->hasMigration('create_scanner_guard_agent_events_table')
            ->hasMigration('create_scanner_guard_agent_metrics_table')
            ->hasCommands([
                SyncDenylistCommand::class,
                AggregateAndPruneCommand::class,
                PullDenylistCommand::class,
            ]);
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

        if (config('scanner-guard.http.server.enabled', false)) {
            $path = config('scanner-guard.http.server.path', 'scanner-guard/bans');

            Route::post($path, RecordForwardedBanController::class)->name('scanner-guard.bans.store');
            Route::get($path, DenylistController::class)->name('scanner-guard.bans.index');
            Route::post("{$path}/heartbeat", RecordAgentHeartbeatController::class)->name('scanner-guard.agents.heartbeat');
            Route::post("{$path}/events", RecordAgentEventController::class)->name('scanner-guard.agents.events');
        }

        $this->app->booted(function (): void {
            $schedule = $this->app->make(Schedule::class);

            // Pulls also re-sync the satellite's sinks.
            if (config('scanner-guard.driver', 'database') === 'http' && config('scanner-guard.http.pull', false)) {
                $schedule->command(PullDenylistCommand::class)->everyMinute()->withoutOverlapping();
            }

            // Both jobs work on the ban/stats tables, which only the
            // database driver has.
            if (config('scanner-guard.driver', 'database') !== 'database') {
                return;
            }

            if ((array) config('scanner-guard.sinks', []) !== []) {
                // Every minute so expired bans leave the sinks promptly; sinks are
                // expected to skip the write when nothing changed.
                $schedule->command(SyncDenylistCommand::class)->everyMinute()->withoutOverlapping();
            }

            if (config('scanner-guard.auto_prune', true)) {
                $schedule->command(AggregateAndPruneCommand::class)->daily();
            }
        });
    }
}
