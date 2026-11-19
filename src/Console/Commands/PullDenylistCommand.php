<?php

declare(strict_types=1);

namespace JeffersonGoncalves\ScannerGuard\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;
use JeffersonGoncalves\ScannerGuard\ScannerGuard;
use Throwable;

/**
 * Satellite side of the http driver: pulls the central app's active bans and
 * static lists, then re-syncs the local denylist sinks when any are configured.
 */
class PullDenylistCommand extends Command
{
    protected $signature = 'scanner-guard:pull-denylist';

    protected $description = 'Pull the central scanner-guard denylist into this satellite';

    public function handle(ScannerGuard $scannerGuard): int
    {
        if ($scannerGuard->driver() !== 'http') {
            $this->warn('Skipped: scanner-guard:pull-denylist requires the "http" driver.');

            return self::SUCCESS;
        }

        try {
            $scannerGuard->pullDenylist();
        } catch (Throwable $e) {
            // The last pulled list stays in place.
            Log::error('scanner-guard: failed to pull denylist', ['exception' => $e->getMessage()]);
            $this->error('Failed to pull the denylist, see the log.');

            return self::FAILURE;
        }

        $this->info(sprintf('Pulled %d active ban(s).', count($scannerGuard->pulledBans())));

        if ((array) config('scanner-guard.sinks', []) !== []) {
            $this->call(SyncDenylistCommand::class);
        }

        return self::SUCCESS;
    }
}
