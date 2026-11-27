<?php

declare(strict_types=1);

namespace JeffersonGoncalves\ScannerGuard\Console\Commands;

use Illuminate\Console\Command;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardBan;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardBlocklistEntry;
use JeffersonGoncalves\ScannerGuard\ScannerGuard;

/**
 * Imports a list of IPs as bans, blocked ranges or ranges never blocked.
 */
class ImportCommand extends Command
{
    protected $signature = 'scanner-guard:import
                            {file : One IP or CIDR per line (first column; # comments)}
                            {--as=ban : ban (bans the IP, like the panel), block (blocklist) or ignore (never block)}
                            {--note= : Note of the block/ignore entries}';

    protected $description = 'Import a list of IPs as bans, blocked ranges or ranges that are never blocked';

    public function handle(ScannerGuard $scannerGuard): int
    {
        $as = $this->option('as');

        if (! in_array($as, ['ban', 'block', 'ignore'], true)) {
            $this->components->error('--as must be ban, block or ignore.');

            return self::FAILURE;
        }

        $lines = @file((string) $this->argument('file'), FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

        if ($lines === false) {
            $this->components->error('Could not read the file.');

            return self::FAILURE;
        }

        $values = collect($lines)
            ->map(fn (string $line): string => (string) preg_split('/\s+/', trim($line))[0])
            ->reject(fn (string $value): bool => $value === '' || str_starts_with($value, '#'))
            ->unique();

        $count = ['new' => 0, 'existing' => 0, 'invalid' => 0, 'ignored' => 0];

        if ($as === 'ban') {
            foreach ($values as $value) {
                if (! filter_var($value, FILTER_VALIDATE_IP)) {
                    $this->invalid($value, $count);

                    continue;
                }

                $ip = $scannerGuard->canonicalIp($value);

                if ($scannerGuard->isBanned($ip)) {
                    $count['existing']++;
                } elseif ($scannerGuard->ban($ip, ScannerGuardBan::REASON_MANUAL, 'import', 0) === null) {
                    $count['ignored']++; // in the never-block list, or not the database driver
                } else {
                    $count['new']++;
                }
            }
        } else {
            $type = $as === 'block' ? ScannerGuardBlocklistEntry::TYPE_IP : ScannerGuardBlocklistEntry::TYPE_IGNORE;

            // Without events: every save re-syncs the sinks; sync once at the end.
            ScannerGuardBlocklistEntry::withoutEvents(function () use ($scannerGuard, $values, $type, &$count): void {
                foreach ($values as $value) {
                    if (! $this->validNetwork($scannerGuard, $value)) {
                        $this->invalid($value, $count);

                        continue;
                    }

                    $entry = ScannerGuardBlocklistEntry::query()->firstOrCreate(
                        ['type' => $type, 'value' => $value],
                        ['note' => $this->option('note')],
                    );

                    $count[$entry->wasRecentlyCreated ? 'new' : 'existing']++;
                }
            });

            if ($count['new'] > 0) {
                $scannerGuard->blocklistChanged();
            }
        }

        $this->components->info(collect($count)->map(fn (int $n, string $label): string => "{$n} {$label}")->implode(', '));

        return self::SUCCESS;
    }

    /** A valid IP or CIDR no wider than /8 (IPv4) or /16 (IPv6), the limit ipIgnore() applies. */
    private function validNetwork(ScannerGuard $scannerGuard, string $value): bool
    {
        $prefix = explode('/', $value, 2)[1] ?? null;

        return $scannerGuard->isValidRange($value)
            && ($prefix === null || (int) $prefix >= (str_contains($value, ':') ? 16 : 8));
    }

    /** @param array<string, int> $count */
    private function invalid(string $value, array &$count): void
    {
        $count['invalid']++;
        $this->components->warn("Invalid: {$value}");
    }
}
