<?php

declare(strict_types=1);

namespace JeffersonGoncalves\ScannerGuard\Jobs;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldBeUniqueUntilProcessing;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Support\Facades\Artisan;
use JeffersonGoncalves\ScannerGuard\Console\Commands\SyncDenylistCommand;

/**
 * Queued on every ban, unban and blocklist change. Unique until it starts, so
 * a burst of bans collapses into one sync, while a ban landing mid-sync still
 * queues the next one.
 */
class SyncDenylist implements ShouldBeUniqueUntilProcessing, ShouldQueue
{
    use Dispatchable;
    use Queueable;

    public function handle(): void
    {
        Artisan::call(SyncDenylistCommand::class);
    }
}
