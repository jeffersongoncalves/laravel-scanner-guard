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
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use InvalidArgumentException;
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
     * "database" (default), "http" (forward bans to a central app) or
     * "cache" (cache-only bans, no audit trail/stats).
     */
    public function driver(): string
    {
        return (string) config('scanner-guard.driver', 'database');
    }

    /**
     * HMAC shared by the http driver client and the receiving route.
     */
    public function sign(string $timestamp, string $body): string
    {
        return hash_hmac('sha256', $timestamp.$body, (string) config('scanner-guard.http.secret'));
    }

    /**
     * Cheap fast path: cache lookup first. With the database driver, falls
     * back to a DB check so a cache flush doesn't silently lift a
     * still-active ban — and re-hydrates the cache entry when it does, so
     * the fallback only ever runs once per ban per cache flush.
     */
    public function isBanned(string $ip): bool
    {
        $hash = $this->hashIp($ip);

        if ($this->cache()->get($this->banKey($hash))) {
            return true;
        }

        if ($this->driver() !== 'database') {
            return false;
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

    /**
     * @return ScannerGuardBan|null the audit row, or null when the driver isn't "database"
     */
    public function ban(string $ip, string $reason, string $matchedValue, int $hitCount, ?string $path = null): ?ScannerGuardBan
    {
        $bannedAt = now();
        $expiresAt = $bannedAt->copy()->addSeconds((int) config('scanner-guard.ban_duration', 86400));

        // Resolved before any cache write, so a bad driver fails without a half-applied ban.
        $persist = match ($this->driver()) {
            'database' => fn (): ScannerGuardBan => $this->storeBan($ip, $reason, $matchedValue, $hitCount, $bannedAt, $expiresAt),
            'http' => fn () => $this->forwardBan([
                'ip' => $ip,
                'reason' => $reason,
                'matched_value' => $matchedValue,
                'hit_count' => $hitCount,
                'path' => $path,
                'banned_at' => $bannedAt->toIso8601String(),
                'expires_at' => $expiresAt->toIso8601String(),
            ]),
            'cache' => fn () => null,
            default => throw new InvalidArgumentException("Unsupported scanner-guard driver [{$this->driver()}]."),
        };

        $this->cacheBan($ip, $expiresAt);
        $this->cache()->forget($this->hitsKey($this->hashIp($ip)));

        $ban = $persist();

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
     * Receiving side of the http driver: records a ban forwarded by a
     * satellite app exactly like a local one, raw IP kept in cache only.
     */
    public function recordForwardedBan(string $ip, string $reason, string $matchedValue, int $hitCount, CarbonInterface $bannedAt, CarbonInterface $expiresAt): ScannerGuardBan
    {
        $this->cacheBan($ip, $expiresAt);

        return $this->storeBan($ip, $reason, $matchedValue, $hitCount, $bannedAt, $expiresAt);
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

    protected function cacheBan(string $ip, CarbonInterface $expiresAt): void
    {
        $hash = $this->hashIp($ip);

        $this->cache()->put($this->banKey($hash), true, $expiresAt);
        // Deliberately the one place a raw IP is cached — required so
        // scanner-guard:export-denylist can write a real `deny <ip>;` line.
        // See README for why this can't live in the (hashed) database row.
        $this->cache()->put($this->rawIpKey($hash), $ip, $expiresAt);
    }

    protected function storeBan(string $ip, string $reason, string $matchedValue, int $hitCount, CarbonInterface $bannedAt, CarbonInterface $expiresAt): ScannerGuardBan
    {
        $ban = ScannerGuardBan::query()->create([
            'ip_hash' => $this->hashIp($ip),
            'reason' => $reason,
            'matched_value' => $matchedValue,
            'hit_count' => $hitCount,
            'banned_at' => $bannedAt,
            'expires_at' => $expiresAt,
        ]);

        $this->recordDailyStats($ban);

        return $ban;
    }

    /**
     * Deferred until after the response is sent, so the remote call never
     * slows down or fails the request; failures are only logged. The raw IP
     * is sent (the central app needs it for the nginx export) but its own
     * salt hashes it — a satellite's ip_hash wouldn't match there.
     *
     * @param  array<string, mixed>  $payload
     */
    protected function forwardBan(array $payload): null
    {
        defer(function () use ($payload): void {
            try {
                $body = (string) json_encode($payload);
                $timestamp = (string) now()->timestamp;

                Http::timeout((int) config('scanner-guard.http.timeout', 2))
                    ->acceptJson()
                    ->withHeaders(['X-Timestamp' => $timestamp, 'X-Signature' => $this->sign($timestamp, $body)])
                    ->withBody($body, 'application/json')
                    ->post((string) config('scanner-guard.http.url'))
                    ->throw();
            } catch (Throwable $e) {
                Log::error('scanner-guard: failed to forward ban', ['exception' => $e->getMessage()]);
            }
        });

        return null;
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
     * Sorted highest first on read: MySQL's JSON type doesn't keep key order.
     *
     * @return array<string, int>
     */
    protected function decodeCounts(?string $json): array
    {
        $counts = array_map('intval', (array) json_decode((string) $json, true));
        arsort($counts);

        return $counts;
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
