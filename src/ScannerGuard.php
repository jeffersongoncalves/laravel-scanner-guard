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
use Illuminate\Support\Str;
use InvalidArgumentException;
use JeffersonGoncalves\ScannerGuard\Jobs\ExportDenylist;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardBan;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardBlocklistEntry;
use JeffersonGoncalves\VisitorFingerprint\Support\IpAnonymizer;
use Symfony\Component\HttpFoundation\IpUtils;
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
     * the fallback only ever runs once per ban per cache flush. A miss is
     * cached as false for negative_cache_ttl seconds so non-banned traffic
     * doesn't hit the database on every request; ban() overwrites it.
     */
    public function isBanned(string $ip): bool
    {
        $hash = $this->hashIp($ip);
        $cached = $this->cache()->get($this->banKey($hash));

        if ($cached !== null) {
            return (bool) $cached;
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
            $this->cache()->put($this->banKey($hash), false, (int) config('scanner-guard.negative_cache_ttl', 60));

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

    /**
     * Static ip_blocklist (IPs and CIDR ranges, IPv4 + IPv6). Not a ban: no
     * row, no expiry.
     */
    public function isIpBlocked(string $ip): bool
    {
        $blocklist = $this->ipBlocklist();

        return $blocklist !== [] && IpUtils::checkIp($ip, $blocklist);
    }

    /**
     * Config ip_blocklist plus the database "ip" entries.
     *
     * @return list<string>
     */
    public function ipBlocklist(): array
    {
        return $this->mergeBlocklist((array) config('scanner-guard.ip_blocklist', []), ScannerGuardBlocklistEntry::TYPE_IP);
    }

    /**
     * Config user_agent_blocklist.patterns plus the database "user_agent" entries.
     *
     * @return list<string>
     */
    public function userAgentPatterns(): array
    {
        return $this->mergeBlocklist((array) config('scanner-guard.user_agent_blocklist.patterns', []), ScannerGuardBlocklistEntry::TYPE_USER_AGENT);
    }

    /**
     * Drops the cached database blocklist and re-exports nginx. Called by
     * ScannerGuardBlocklistEntry on save/delete.
     */
    public function blocklistChanged(): void
    {
        // A new version, not a forget(): a read still in flight from before the
        // change can only fill the old version's key, never the current one.
        $this->cache()->forever($this->blocklistVersionKey(), Str::random(16));
        $this->queueNginxExport();
    }

    /**
     * Lifts every active ban of $ipHash at once. Deleting the row alone
     * isn't enough: the cached ban would keep answering "banned" until it
     * expires.
     *
     * @return int ban rows deleted (always 0 without the database driver)
     */
    public function unban(string $ipHash): int
    {
        $deleted = $this->driver() === 'database'
            ? ScannerGuardBan::query()->where('ip_hash', $ipHash)->active()->delete()
            : 0;

        $this->cache()->forget($this->banKey($ipHash));
        $this->cache()->forget($this->rawIpKey($ipHash));
        // So a manual unban doesn't swallow a fresh ban of the same IP right after.
        $this->cache()->forget($this->banningKey($ipHash));
        $this->queueNginxExport();

        return (int) $deleted;
    }

    /**
     * @param  array<mixed>  $configured
     * @return list<string>
     */
    protected function mergeBlocklist(array $configured, string $type): array
    {
        return array_values(array_unique(array_map('strval', [...$configured, ...($this->databaseBlocklist()[$type] ?? [])])));
    }

    /**
     * Read from cache on every call rather than merged into config at boot,
     * so queue workers and Octane see a change without re-booting. Two cache
     * reads per check (version + list); the query only runs after
     * blocklistChanged(). The day TTL only expires superseded versions.
     *
     * @return array<string, list<string>>
     */
    protected function databaseBlocklist(): array
    {
        if ($this->driver() !== 'database') {
            return [];
        }

        $version = (string) $this->cache()->rememberForever($this->blocklistVersionKey(), fn (): string => Str::random(16));
        $key = $this->blocklistKey($version);

        try {
            /** @var array<string, list<string>> */
            return $this->cache()->remember($key, now()->addDay(), fn (): array => ScannerGuardBlocklistEntry::query()
                ->orderBy('id')
                ->get(['type', 'value'])
                ->groupBy('type')
                ->map(fn (Collection $group): array => $group->pluck('value')->all())
                ->all());
        } catch (Throwable $e) {
            // e.g. the blocklist migration not run yet: fall back to config,
            // and only retry the query once per negative_cache_ttl.
            report($e);
            $this->cache()->put($key, [], max((int) config('scanner-guard.negative_cache_ttl', 60), 1));

            return [];
        }
    }

    /**
     * @return string|null "empty" (block_empty) or the matched pattern, null when the UA passes
     */
    public function matchUserAgent(?string $userAgent): ?string
    {
        $userAgent = trim((string) $userAgent);

        if ($userAgent === '') {
            return config('scanner-guard.user_agent_blocklist.block_empty', false) ? 'empty' : null;
        }

        foreach ($this->userAgentPatterns() as $pattern) {
            if (fnmatch($pattern, $userAgent, FNM_CASEFOLD)) {
                return $pattern;
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
        return $this->increment($this->hitsKey($this->hashIp($ip)), (int) config('scanner-guard.ban_window', 300));
    }

    /**
     * Same as registerHit(), but for the opt-in 404-flood counter
     * (TTL = not_found_window).
     */
    public function registerNotFoundHit(string $ip): int
    {
        return $this->increment($this->notFoundKey($this->hashIp($ip)), (int) config('scanner-guard.not_found_window', 60));
    }

    protected function increment(string $key, int $window): int
    {
        // add() only writes when missing, atomically — has()+put() could reset a concurrent increment.
        $this->cache()->add($key, 0, $window);

        return (int) $this->cache()->increment($key);
    }

    /**
     * @return ScannerGuardBan|null the audit row, or null when the driver isn't "database"
     *                              or another request of the same burst already banned this IP
     */
    public function ban(string $ip, string $reason, string $matchedValue, int $hitCount, ?string $path = null): ?ScannerGuardBan
    {
        if (! $this->claimBan($this->hashIp($ip))) {
            return null;
        }

        $bannedAt = now();
        $offense = $this->nextOffense($this->hashIp($ip), $reason);
        $expiresAt = $bannedAt->copy()->addSeconds($this->banDuration($offense));

        // Resolved before any cache write, so a bad driver fails without a half-applied ban.
        $persist = match ($this->driver()) {
            'database' => fn (): ScannerGuardBan => $this->storeBan($ip, $reason, $matchedValue, $hitCount, $bannedAt, $expiresAt, $offense),
            // The satellite decides the escalation; the central app stores its offense as-is.
            'http' => fn () => $this->forwardBan([
                'ip' => $ip,
                'reason' => $reason,
                'matched_value' => $matchedValue,
                'hit_count' => $hitCount,
                'path' => $path,
                'banned_at' => $bannedAt->toIso8601String(),
                'expires_at' => $expiresAt->toIso8601String(),
                'offense' => $offense,
            ]),
            'cache' => fn () => null,
            default => throw new InvalidArgumentException("Unsupported scanner-guard driver [{$this->driver()}]."),
        };

        $this->cacheBan($ip, $expiresAt);
        $this->cache()->forget($this->hitsKey($this->hashIp($ip)));
        $this->cache()->forget($this->notFoundKey($this->hashIp($ip)));

        $ban = $persist();

        Log::warning('scanner-guard: banned ip', array_filter([
            'ip' => $ip,
            'path' => $path,
            'reason' => $reason,
            'matched_value' => $matchedValue,
            'hit_count' => $hitCount,
            'expires_at' => $expiresAt->toIso8601String(),
            'offense' => $offense,
        ], fn ($value) => $value !== null));

        return $ban;
    }

    /**
     * Receiving side of the http driver: records a ban forwarded by a
     * satellite app exactly like a local one, raw IP kept in cache only.
     * Null when this IP was already banned moments ago (e.g. several
     * satellites behind a load balancer forwarding the same burst).
     */
    public function recordForwardedBan(string $ip, string $reason, string $matchedValue, int $hitCount, CarbonInterface $bannedAt, CarbonInterface $expiresAt, ?int $offense = null): ?ScannerGuardBan
    {
        if (! $this->claimBan($this->hashIp($ip))) {
            return null;
        }

        $this->cacheBan($ip, $expiresAt);

        return $this->storeBan($ip, $reason, $matchedValue, $hitCount, $bannedAt, $expiresAt, $offense);
    }

    /**
     * Concurrent requests of one burst all pass isBanned() before the first
     * ban is cached, and each would store its own row with a climbing
     * offense. add() is atomic: only the first caller wins.
     */
    protected function claimBan(string $hash): bool
    {
        // ponytail: fixed 60s, just needs to outlive a burst; the shortest ban is far longer.
        return $this->cache()->add($this->banningKey($hash), true, 60);
    }

    public function escalationEnabled(): bool
    {
        return (array) config('scanner-guard.escalation', []) !== [];
    }

    public function escalationLookbackDays(): int
    {
        return (int) config('scanner-guard.escalation_lookback_days', 365);
    }

    /**
     * @return int|null 1 for a first offense, or null when this ban doesn't escalate
     */
    protected function nextOffense(string $hash, string $reason): ?int
    {
        $reasons = (array) config('scanner-guard.escalation_reasons', []);

        if (! $this->escalationEnabled() || ! in_array($reason, $reasons, true)) {
            return null;
        }

        $lookback = $this->escalationLookbackDays();

        return match ($this->driver()) {
            'database' => (int) ScannerGuardBan::query()
                ->where('ip_hash', $hash)
                ->whereIn('reason', $reasons)
                ->where('banned_at', '>=', now()->subDays($lookback))
                ->max('offense') + 1,
            'cache', 'http' => $this->bumpOffenses($hash, $lookback),
            default => null, // ban() rejects the driver before any write
        };
    }

    /**
     * Best effort: the counter is gone after a cache flush. TTL restarts at
     * every ban, so the lookback runs from the latest one, like the
     * database lookup.
     */
    protected function bumpOffenses(string $hash, int $lookbackDays): int
    {
        // ponytail: get+put isn't atomic; two bans of one IP at the same instant only lose a step.
        $offense = (int) $this->cache()->get($this->offensesKey($hash)) + 1;
        $this->cache()->put($this->offensesKey($hash), $offense, now()->addDays($lookbackDays));

        return $offense;
    }

    protected function banDuration(?int $offense): int
    {
        if ($offense === null) {
            return (int) config('scanner-guard.ban_duration', 86400);
        }

        $steps = array_values((array) config('scanner-guard.escalation'));

        return (int) $steps[min($offense, count($steps)) - 1];
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

    protected function storeBan(string $ip, string $reason, string $matchedValue, int $hitCount, CarbonInterface $bannedAt, CarbonInterface $expiresAt, ?int $offense = null): ScannerGuardBan
    {
        // offense only when set, so apps that never ran the add_offense migration keep working.
        $ban = ScannerGuardBan::query()->create(array_filter([
            'ip_hash' => $this->hashIp($ip),
            'reason' => $reason,
            'matched_value' => $matchedValue,
            'hit_count' => $hitCount,
            'banned_at' => $bannedAt,
            'expires_at' => $expiresAt,
            'offense' => $offense,
        ], fn ($value) => $value !== null));

        $this->recordDailyStats($ban);

        if (config('scanner-guard.nginx.export_on_ban', true)) {
            $this->queueNginxExport();
        }

        return $ban;
    }

    /**
     * Keeps the nginx denylist within seconds of the ban table and blocklist
     * instead of a minute behind. A queue failure is logged, never breaks the
     * ban, unban or blocklist change.
     */
    protected function queueNginxExport(): void
    {
        if (! config('scanner-guard.sync_to_nginx', false)) {
            return;
        }

        try {
            ExportDenylist::dispatch();
        } catch (Throwable $e) {
            Log::error('scanner-guard: failed to queue nginx export', ['exception' => $e->getMessage()]);
        }
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

    protected function banningKey(string $hash): string
    {
        return "scanner-guard:banning:{$hash}";
    }

    protected function hitsKey(string $hash): string
    {
        return "scanner-guard:hits:{$hash}";
    }

    protected function notFoundKey(string $hash): string
    {
        return "scanner-guard:not-found:{$hash}";
    }

    protected function offensesKey(string $hash): string
    {
        return "scanner-guard:offenses:{$hash}";
    }

    protected function rawIpKey(string $hash): string
    {
        return "scanner-guard:raw-ip:{$hash}";
    }

    protected function blocklistKey(string $version): string
    {
        return "scanner-guard:blocklist:{$version}";
    }

    protected function blocklistVersionKey(): string
    {
        return 'scanner-guard:blocklist-version';
    }
}
