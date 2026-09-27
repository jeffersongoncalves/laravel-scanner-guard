<?php

declare(strict_types=1);

namespace JeffersonGoncalves\ScannerGuard;

use Carbon\CarbonInterface;
use Carbon\CarbonPeriod;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Support\Carbon;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardBan;
use JeffersonGoncalves\VisitorFingerprint\Support\IpAnonymizer;
use Throwable;

/**
 * Core ban/hit-counting logic, shared by the middleware and the export
 * command. Every cache key is keyed by the salted IP hash rather than the
 * raw IP, EXCEPT the deliberate "raw-ip" entry written at ban time, whose
 * whole purpose is to let scanner-guard:export-denylist reproduce a real IP
 * for nginx — see the README's "Privacy tradeoff" section.
 */
class ScannerGuard
{
    public function cache(): Repository
    {
        return Cache::store(config('scanner-guard.store'));
    }

    public function hashIp(string $ip): string
    {
        return IpAnonymizer::hash($ip);
    }

    /**
     * Cheap fast path: cache lookup first. Falls back to a DB check so a
     * cache flush doesn't silently lift a still-active ban — and
     * re-hydrates the cache entry when it does, so the fallback only ever
     * runs once per ban per cache flush.
     */
    public function isBanned(string $ip): bool
    {
        $hash = $this->hashIp($ip);

        if ($this->cache()->get($this->banKey($hash))) {
            return true;
        }

        $ban = ScannerGuardBan::query()
            ->where('ip_hash', $hash)
            ->active()
            ->latest('expires_at')
            ->first();

        if (! $ban) {
            return false;
        }

        $this->cache()->put($this->banKey($hash), true, $ban->expires_at);

        return true;
    }

    /**
     * @return string|null the matched pattern, or null when the path doesn't match any scanner pattern
     */
    public function matchScannerPath(string $path): ?string
    {
        $path = ltrim($path, '/');

        foreach ((array) config('scanner-guard.scanner_paths', []) as $pattern) {
            if (fnmatch((string) $pattern, $path, FNM_CASEFOLD)) {
                return (string) $pattern;
            }
        }

        return null;
    }

    public function isAsnBlocked(?string $asn): bool
    {
        if ($asn === null || $asn === '') {
            return false;
        }

        $blocklist = (array) config('scanner-guard.asn_blocklist', []);

        if ($blocklist === []) {
            return false;
        }

        // Some GeoIP drivers return a descriptive string like
        // "AS16276 OVH SAS" instead of a bare "AS16276" — match on the
        // leading token too so either form works against the blocklist.
        [$token] = explode(' ', $asn, 2);

        return in_array($asn, $blocklist, true) || in_array($token, $blocklist, true);
    }

    /**
     * Increments the rolling per-IP hit counter (TTL = ban_window) and
     * returns the new count.
     */
    public function registerHit(string $ip): int
    {
        $hash = $this->hashIp($ip);
        $key = $this->hitsKey($hash);
        $window = (int) config('scanner-guard.ban_window', 300);

        if (! $this->cache()->has($key)) {
            $this->cache()->put($key, 0, $window);
        }

        return (int) $this->cache()->increment($key);
    }

    public function ban(string $ip, string $reason, string $matchedValue, int $hitCount, ?string $path = null): ScannerGuardBan
    {
        $hash = $this->hashIp($ip);
        $duration = (int) config('scanner-guard.ban_duration', 86400);
        $expiresAt = now()->addSeconds($duration);

        $this->cache()->put($this->banKey($hash), true, $expiresAt);
        // Deliberately the one place a raw IP is cached — required so
        // scanner-guard:export-denylist can write a real `deny <ip>;` line.
        // See README for why this can't live in the (hashed) database row.
        $this->cache()->put($this->rawIpKey($hash), $ip, $expiresAt);
        $this->cache()->forget($this->hitsKey($hash));

        $ban = ScannerGuardBan::query()->create([
            'ip_hash' => $hash,
            'reason' => $reason,
            'matched_value' => $matchedValue,
            'hit_count' => $hitCount,
            'banned_at' => now(),
            'expires_at' => $expiresAt,
        ]);

        $this->recordDailyStats($ban);

        Log::warning('scanner-guard: banned ip', array_filter([
            'ip' => $ip,
            'path' => $path,
            'reason' => $reason,
            'matched_value' => $matchedValue,
            'hit_count' => $hitCount,
            'expires_at' => $expiresAt->toIso8601String(),
        ], fn ($value) => $value !== null));

        return $ban;
    }

    /**
     * Best-effort: returns the raw IP cached at ban time, or null when it
     * has since expired/been evicted (cache flush, "array" driver, etc.).
     */
    public function rawIpFor(string $ipHash): ?string
    {
        return $this->cache()->get($this->rawIpKey($ipHash));
    }

    /**
     * One entry per day for the last $days days (today included, oldest
     * first), zero-filled for days without a stats row. Today's entry is the
     * live counter bumped at ban time.
     *
     * @return Collection<int, array{date: string, bans_count: int, hits_total: int, reason_stats: array<string, int>, top_matched_values: array<string, int>}>
     */
    public function dailyStats(int $days = 14): Collection
    {
        $from = Carbon::today()->subDays(max($days, 1) - 1);

        $rows = DB::table($this->dailyStatsTable())
            ->where('date', '>=', $from->toDateString())
            ->get()
            ->keyBy(fn ($row): string => Carbon::parse($row->date)->toDateString());

        return collect(CarbonPeriod::create($from, Carbon::today()))
            ->map(function (CarbonInterface $day) use ($rows): array {
                $date = $day->toDateString();
                $row = $rows->get($date);

                return [
                    'date' => $date,
                    'bans_count' => (int) ($row->bans_count ?? 0),
                    'hits_total' => (int) ($row->hits_total ?? 0),
                    'reason_stats' => $this->decodeCounts($row->reason_stats ?? null),
                    'top_matched_values' => $this->decodeCounts($row->top_matched_values ?? null),
                ];
            })
            ->values();
    }

    /**
     * Folds $stats into the daily_stats row for $date, creating it if
     * missing. $combine(existing, incoming) decides each counter's new value
     * — `+` for ban-time increments, `max` for the daily reconcile.
     *
     * @param  array{bans_count: int, hits_total: int, reason_stats: array<string, int>, top_matched_values: array<string, int>}  $stats
     * @param  callable(int, int): int  $combine
     */
    public function mergeDailyStats(string $date, array $stats, callable $combine): void
    {
        $table = $this->dailyStatsTable();

        DB::transaction(function () use ($table, $date, $stats, $combine): void {
            DB::table($table)->insertOrIgnore([
                'date' => $date,
                'bans_count' => 0,
                'hits_total' => 0,
                'created_at' => now(),
                'updated_at' => now(),
            ]);

            $row = DB::table($table)->where('date', $date)->lockForUpdate()->first();

            $mergeMap = function (array $existing, array $incoming) use ($combine): array {
                foreach ($incoming as $key => $value) {
                    $existing[$key] = $combine($existing[$key] ?? 0, $value);
                }

                arsort($existing);

                return $existing;
            };

            DB::table($table)->where('date', $date)->update([
                'bans_count' => $combine((int) $row->bans_count, $stats['bans_count']),
                'hits_total' => $combine((int) $row->hits_total, $stats['hits_total']),
                'reason_stats' => json_encode($mergeMap($this->decodeCounts($row->reason_stats), $stats['reason_stats'])),
                'top_matched_values' => json_encode($mergeMap($this->decodeCounts($row->top_matched_values), $stats['top_matched_values'])),
                'updated_at' => now(),
            ]);
        });
    }

    public function dailyStatsTable(): string
    {
        return config('scanner-guard.daily_stats_table', 'scanner_guard_ban_daily_stats');
    }

    /**
     * Counted at ban time so the daily history survives any later delete of
     * the ban row (purge, unban, retention prune). Never lets a stats failure
     * (e.g. the stats migration not published yet) break the ban itself.
     */
    protected function recordDailyStats(ScannerGuardBan $ban): void
    {
        try {
            $this->mergeDailyStats($ban->banned_at->toDateString(), [
                'bans_count' => 1,
                'hits_total' => $ban->hit_count,
                'reason_stats' => [$ban->reason => 1],
                'top_matched_values' => [$ban->matched_value => $ban->hit_count],
            ], fn (int $a, int $b): int => $a + $b);
        } catch (Throwable $e) {
            Log::error('scanner-guard: failed to record daily stats', ['exception' => $e->getMessage()]);
        }
    }

    /**
     * @return array<string, int>
     */
    protected function decodeCounts(?string $json): array
    {
        return array_map('intval', (array) json_decode((string) $json, true));
    }

    protected function banKey(string $hash): string
    {
        return "scanner-guard:ban:{$hash}";
    }

    protected function hitsKey(string $hash): string
    {
        return "scanner-guard:hits:{$hash}";
    }

    protected function rawIpKey(string $hash): string
    {
        return "scanner-guard:raw-ip:{$hash}";
    }
}
