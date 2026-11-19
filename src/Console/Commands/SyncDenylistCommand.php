<?php

declare(strict_types=1);

namespace JeffersonGoncalves\ScannerGuard\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Support\Facades\Log;
use JeffersonGoncalves\ScannerGuard\Contracts\DenylistSink;
use JeffersonGoncalves\ScannerGuard\ScannerGuard;
use Throwable;

/**
 * Pushes the current denylist (static ip_blocklist + active bans whose raw IP
 * is still cached, see the README's "Privacy tradeoff") to every sink in
 * scanner-guard.sinks. A failing sink is logged and doesn't stop the others.
 */
class SyncDenylistCommand extends Command
{
    protected $signature = 'scanner-guard:sync-denylist';

    protected $description = 'Push active scanner-guard bans and the ip_blocklist to every configured denylist sink';

    public function handle(ScannerGuard $scannerGuard): int
    {
        // http: syncs what scanner-guard:pull-denylist fetched from the central app.
        if (! in_array($scannerGuard->driver(), ['database', 'http'], true)) {
            $this->warn('Skipped: scanner-guard:sync-denylist requires the "database" or "http" driver.');

            return self::SUCCESS;
        }

        $sinks = $scannerGuard->sinks();

        if ($sinks === []) {
            $this->warn('Skipped: no sinks configured in scanner-guard.sinks.');

            return self::SUCCESS;
        }

        // One lock around read + push, shared by the on-change job and the
        // schedule: a slower sync can never overwrite a newer snapshot.
        $store = $scannerGuard->cache()->getStore();

        if ($store instanceof LockProvider) {
            return $store->lock('scanner-guard:sync-denylist', 120)->block(60, fn (): int => $this->sync($scannerGuard, $sinks));
        }

        return $this->sync($scannerGuard, $sinks);
    }

    /**
     * @param  list<DenylistSink>  $sinks
     */
    protected function sync(ScannerGuard $scannerGuard, array $sinks): int
    {
        $entries = $scannerGuard->denylistEntries();
        $failed = false;

        foreach ($sinks as $sink) {
            try {
                $sink->sync($entries);
                $this->info(sprintf('%s: synced %d entr%s.', $sink::class, count($entries), count($entries) === 1 ? 'y' : 'ies'));
            } catch (Throwable $e) {
                $failed = true;
                Log::error('scanner-guard: denylist sink failed', ['sink' => $sink::class, 'exception' => $e->getMessage()]);
                $this->error(sprintf('%s failed, see the log.', $sink::class));
            }
        }

        return $failed ? self::FAILURE : self::SUCCESS;
    }
}
