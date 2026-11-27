<?php

declare(strict_types=1);

namespace JeffersonGoncalves\ScannerGuard\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static \Illuminate\Contracts\Cache\Repository cache()
 * @method static string hashIp(string $ip)
 * @method static string canonicalIp(string $ip)
 * @method static bool isValidRange(string $entry)
 * @method static bool isBanned(string $ip)
 * @method static string|null matchScannerPath(string $path)
 * @method static bool isAsnBlocked(string|null $asn)
 * @method static int registerHit(string $ip)
 * @method static string driver()
 * @method static string sign(string $timestamp, string $body)
 * @method static string signResponse(string $timestamp, string $requestSignature, string $source, string $body, string|null $secret = null)
 * @method static \JeffersonGoncalves\ScannerGuard\Models\ScannerGuardBan|null ban(string $ip, string $reason, string $matchedValue, int $hitCount, string|null $path = null)
 * @method static \JeffersonGoncalves\ScannerGuard\Models\ScannerGuardBan|null recordForwardedBan(string $ip, string $reason, string $matchedValue, int $hitCount, \Carbon\CarbonInterface $bannedAt, \Carbon\CarbonInterface $expiresAt, ?int $offense = null, string|null $source = null, string|null $path = null, array|null $evidence = null)
 * @method static int unban(string $ipHash)
 * @method static list<string> ipBlocklist()
 * @method static bool isIpIgnored(string $ip)
 * @method static list<string> ipIgnore()
 * @method static list<string> userAgentPatterns()
 * @method static array<string, array{threshold: int, window: int, ban: list<int>}>|null agentRules()
 * @method static \JeffersonGoncalves\ScannerGuard\Models\ScannerGuardAgentEvent|null recordAgentEvent(string $source, string $rule, string $ip, ?string $pattern, array $fields, ?string $line, bool $ignored, \Carbon\CarbonInterface $at)
 * @method static void recordAgentMatches(string $source, array $matches)
 * @method static bool hasTable(string $model)
 * @method static void blocklistChanged()
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
