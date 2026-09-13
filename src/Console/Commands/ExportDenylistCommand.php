<?php

declare(strict_types=1);

namespace JeffersonGoncalves\ScannerGuard\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\File;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardBan;
use JeffersonGoncalves\ScannerGuard\ScannerGuard;

/**
 * Writes currently-active bans as nginx `deny <ip>;` lines. Only bans whose
 * raw IP is still recoverable from cache are included — see the README's
 * "Privacy tradeoff" section for why the permanent (hashed) ban table alone
 * can't feed this export.
 */
class ExportDenylistCommand extends Command
{
    protected $signature = 'scanner-guard:export-denylist {--path=storage/app/scanner-guard/denylist.conf}';

    protected $description = 'Export active scanner-guard bans as an nginx deny-list file';

    public function handle(ScannerGuard $scannerGuard): int
    {
        $bans = ScannerGuardBan::query()->active()->get();

        $lines = [];
        $skipped = 0;

        foreach ($bans as $ban) {
            $ip = $scannerGuard->rawIpFor($ban->ip_hash);

            if ($ip === null) {
                $skipped++;

                continue;
            }

            $lines[] = "deny {$ip}; # {$ban->reason}, expires {$ban->expires_at->toIso8601String()}";
        }

        $path = base_path((string) $this->option('path'));

        File::ensureDirectoryExists(dirname($path));

        $lines = array_values(array_unique($lines));

        File::put($path, implode(PHP_EOL, $lines).PHP_EOL);

        $this->info(sprintf('Wrote %d deny rule(s) to %s.', count($lines), $path));

        if ($skipped > 0) {
            $this->warn(sprintf(
                '%d active ban(s) skipped: raw IP no longer cached (evicted/flushed). They remain blocked at the app layer.',
                $skipped
            ));
        }

        return self::SUCCESS;
    }
}
