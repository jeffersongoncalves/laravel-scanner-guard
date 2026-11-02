<?php

declare(strict_types=1);

namespace JeffersonGoncalves\ScannerGuard\Jobs;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldBeUniqueUntilProcessing;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Support\Facades\Artisan;
use JeffersonGoncalves\ScannerGuard\Console\Commands\ExportDenylistCommand;

/**
 * Queued on every new ban. Unique until it starts, so a burst of bans
 * collapses into one export, while a ban landing mid-export still queues
 * the next one.
 */
class ExportDenylist implements ShouldBeUniqueUntilProcessing, ShouldQueue
{
    use Dispatchable;
    use Queueable;

    public function handle(): void
    {
        Artisan::call(ExportDenylistCommand::class);
    }
}
