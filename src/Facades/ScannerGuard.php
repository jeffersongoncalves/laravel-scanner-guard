<?php

declare(strict_types=1);

namespace JeffersonGoncalves\ScannerGuard\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static \Illuminate\Contracts\Cache\Repository cache()
 * @method static string hashIp(string $ip)
 * @method static bool isBanned(string $ip)
 * @method static string|null matchScannerPath(string $path)
 * @method static bool isAsnBlocked(string|null $asn)
 * @method static int registerHit(string $ip)
 * @method static \JeffersonGoncalves\ScannerGuard\Models\ScannerGuardBan ban(string $ip, string $reason, string $matchedValue, int $hitCount, string|null $path = null)
 * @method static string|null rawIpFor(string $ipHash)
 * @method static \Illuminate\Support\Collection<int, array{date: string, bans_count: int, hits_total: int, reason_stats: array<string, int>, top_matched_values: array<string, int>}> dailyStats(int $days = 14)
 * @method static void mergeDailyStats(string $date, array $stats, callable $combine)
 * @method static string dailyStatsTable()
 *
 * @see \JeffersonGoncalves\ScannerGuard\ScannerGuard
 */
class ScannerGuard extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return 'laravel-scanner-guard';
    }
}
