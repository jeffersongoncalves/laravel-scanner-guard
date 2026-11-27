<?php

declare(strict_types=1);

namespace JeffersonGoncalves\ScannerGuard\Console\Commands;

use Illuminate\Console\Command;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardBan;
use JeffersonGoncalves\ScannerGuard\ScannerGuard;
use Symfony\Component\HttpFoundation\IpUtils;

/**
 * Groups the banned IPs by /24 and /16 to spot bot networks worth blocking
 * as a whole. Needs store_details: only those bans keep the IP.
 */
class BanReportCommand extends Command
{
    protected $signature = 'scanner-guard:ban-report
                            {--min=3 : Minimum distinct IPs in a range}
                            {--reason= : Only bans with this reason (e.g. ssh_bruteforce, web_attack)}
                            {--days= : Only bans from the last N days}';

    protected $description = 'Group banned IPs by /24 and /16 to find bot networks, flagging the ranges already blocked';

    public function handle(ScannerGuard $scannerGuard): int
    {
        $query = ScannerGuardBan::query()->whereNotNull('ip');

        if ($reason = $this->option('reason')) {
            $query->where('reason', $reason);
        }

        if ($days = $this->option('days')) {
            $query->where('banned_at', '>=', now()->subDays((int) $days));
        }

        $blocklist = $scannerGuard->ipBlocklist();
        $groups = [24 => [], 16 => []];

        // The IP is encrypted in the database: grouping happens after reading each row.
        // ponytail: IPv4 only; group IPv6 by /48 once bots show up over IPv6.
        foreach ($query->cursor() as $ban) {
            $ip = (string) $ban->ip;

            if (! filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                continue;
            }

            [$a, $b, $c] = explode('.', $ip);

            foreach ([24 => "{$a}.{$b}.{$c}.0/24", 16 => "{$a}.{$b}.0.0/16"] as $len => $net) {
                $group = $groups[$len][$net] ?? ['ips' => [], 'bans' => 0, 'sources' => [], 'reasons' => [], 'first' => $ban->banned_at, 'last' => $ban->banned_at];
                $group['ips'][$ip] = true;
                $group['bans']++;
                $group['sources'][$ban->source ?? 'local'] = true;
                $group['reasons'][$ban->reason] = true;
                $group['first'] = $ban->banned_at->min($group['first']);
                $group['last'] = $ban->banned_at->max($group['last']);
                $groups[$len][$net] = $group;
            }
        }

        if ($groups[16] === []) {
            $this->components->warn('No banned IPv4 address stored: the report needs store_details (only those bans keep the IP).');

            return self::SUCCESS;
        }

        $min = (int) $this->option('min');

        foreach ($groups as $len => $nets) {
            $rows = collect($nets)
                ->filter(fn (array $g): bool => count($g['ips']) >= $min)
                ->sortByDesc(fn (array $g): int => count($g['ips']))
                ->map(fn (array $g, string $net): array => [
                    $net,
                    count($g['ips']),
                    $g['bans'],
                    count($g['sources']),
                    implode(', ', array_keys($g['reasons'])),
                    $g['first']->format('Y-m-d').' to '.$g['last']->format('Y-m-d'),
                    $this->covered($net, $len, $blocklist) ? 'yes' : '',
                ]);

            $this->components->info("/{$len} ranges with {$min}+ IPs");
            $this->table(['Range', 'IPs', 'Bans', 'Sources', 'Reasons', 'Period', 'Blocked'], $rows->values()->all());
        }

        return self::SUCCESS;
    }

    /**
     * A blocklist IPv4 entry as wide as the range or wider that holds its base
     * address: a narrower one (a /32, a /25 of a /24) blocks only part of it.
     *
     * @param  list<string>  $blocklist
     */
    private function covered(string $net, int $len, array $blocklist): bool
    {
        $base = explode('/', $net)[0];

        foreach ($blocklist as $entry) {
            if (! str_contains($entry, ':') && (int) (explode('/', $entry, 2)[1] ?? 32) <= $len && IpUtils::checkIp($base, $entry)) {
                return true;
            }
        }

        return false;
    }
}
