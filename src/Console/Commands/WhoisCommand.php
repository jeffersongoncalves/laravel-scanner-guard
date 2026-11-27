<?php

declare(strict_types=1);

namespace JeffersonGoncalves\ScannerGuard\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Process;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardBan;
use Symfony\Component\HttpFoundation\IpUtils;

/**
 * Lists the banned IPs of a range with their owner, to decide whether the
 * whole range is worth blocking. Needs the system `whois` binary.
 */
class WhoisCommand extends Command
{
    protected $signature = 'scanner-guard:whois
                            {network : IP or range, e.g. 207.175.0.0/16}
                            {--limit=10 : Maximum IPs looked up with whois}';

    protected $description = 'List the banned IPs of a range with their owner (whois)';

    public function handle(): int
    {
        $network = (string) $this->argument('network');
        $bans = [];

        // The IP is encrypted in the database: filtering happens after reading each row.
        foreach (ScannerGuardBan::query()->whereNotNull('ip')->cursor() as $ban) {
            if (IpUtils::checkIp((string) $ban->ip, $network)) {
                $bans[(string) $ban->ip][] = $ban->reason;
            }
        }

        if ($bans === []) {
            $this->components->warn("No banned IP in {$network}; looking up the address itself.");
            $bans[explode('/', $network)[0]] = [];
        }

        $rows = collect($bans)
            ->take((int) $this->option('limit'))
            ->map(fn (array $reasons, string $ip): array => [
                $ip,
                count($reasons),
                implode(', ', array_unique($reasons)),
                ...$this->whois($ip),
            ]);

        $this->table(['IP', 'Bans', 'Reasons', 'Owner', 'Network', 'Country'], $rows->values()->all());

        if (count($bans) > $rows->count()) {
            $this->components->info(count($bans).' IPs in the range, '.$rows->count().' looked up (--limit).');
        }

        return self::SUCCESS;
    }

    /** @return array{string, string, string} owner, network name and country */
    private function whois(string $ip): array
    {
        $result = Process::timeout(15)->run(['whois', $ip]);

        if (! $result->successful() && $result->output() === '') {
            return ['(whois failed: '.trim($result->errorOutput()).')', '', ''];
        }

        // ARIN uses OrgName, RIPE/APNIC org-name/descr, LACNIC owner.
        $field = function (array $keys) use ($result): string {
            foreach ($keys as $key) {
                if (preg_match('/^'.$key.':\s*(.+)$/mi', $result->output(), $m)) {
                    return trim($m[1]);
                }
            }

            return '';
        };

        return [
            $field(['OrgName', 'org-name', 'owner', 'descr']),
            $field(['NetName', 'netname']),
            strtoupper($field(['Country', 'country'])),
        ];
    }
}
