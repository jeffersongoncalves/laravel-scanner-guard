<?php

declare(strict_types=1);

namespace JeffersonGoncalves\ScannerGuard\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Process;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardBan;
use JeffersonGoncalves\ScannerGuard\ScannerGuard;
use Throwable;

/**
 * Writes currently-active bans as nginx `deny <ip>;` lines. Only bans whose
 * raw IP is still recoverable from cache are included — see the README's
 * "Privacy tradeoff" section for why the permanent (hashed) ban table alone
 * can't feed this export.
 */
class ExportDenylistCommand extends Command
{
    protected $signature = 'scanner-guard:export-denylist {--path= : Relative to base_path(); defaults to scanner-guard.nginx.path}';

    protected $description = 'Export active scanner-guard bans as an nginx deny-list file';

    public function handle(ScannerGuard $scannerGuard): int
    {
        if ($scannerGuard->driver() !== 'database') {
            $this->warn('Skipped: scanner-guard:export-denylist requires the "database" driver.');

            return self::SUCCESS;
        }

        // One lock around read + write + reload, shared by the on-ban job and the
        // schedule: a slower export can never overwrite a newer snapshot.
        $store = $scannerGuard->cache()->getStore();

        if ($store instanceof LockProvider) {
            return $store->lock('scanner-guard:export-denylist', 120)->block(60, fn (): int => $this->export($scannerGuard));
        }

        return $this->export($scannerGuard);
    }

    protected function export(ScannerGuard $scannerGuard): int
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

        $path = base_path((string) ($this->option('path') ?? config('scanner-guard.nginx.path', 'storage/app/scanner-guard/denylist.conf')));

        File::ensureDirectoryExists(dirname($path));

        $lines = array_values(array_unique($lines));
        $contents = implode(PHP_EOL, $lines).PHP_EOL;
        $changed = ! File::exists($path) || File::get($path) !== $contents;

        if ($changed) {
            // Temp file + rename: an nginx reload mid-write never reads a truncated file.
            $temp = $path.'.'.bin2hex(random_bytes(4)).'.tmp';
            File::put($temp, $contents);
            File::move($temp, $path);
        }

        $this->info(sprintf('Wrote %d deny rule(s) to %s.', count($lines), $path));

        if ($changed) {
            $this->reload();
        }

        if ($skipped > 0) {
            $this->warn(sprintf(
                '%d active ban(s) skipped: raw IP no longer cached (evicted/flushed). They remain blocked at the app layer.',
                $skipped
            ));
        }

        return self::SUCCESS;
    }

    protected function reload(): void
    {
        $command = config('scanner-guard.nginx.reload_command');

        if ($command === null || $command === '') {
            return;
        }

        try {
            $result = Process::run((string) $command);
            $error = $result->failed() ? 'exit '.$result->exitCode().': '.trim($result->errorOutput() ?: $result->output()) : null;
        } catch (Throwable $e) {
            // Timeout or the command can't start: the file is already written, so only report it.
            $error = $e->getMessage();
        }

        if ($error !== null) {
            Log::error('scanner-guard: nginx reload command failed', ['command' => $command, 'error' => $error]);
            $this->warn('nginx reload command failed, see the log.');
        }
    }
}
