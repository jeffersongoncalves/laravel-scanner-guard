<?php

declare(strict_types=1);

namespace JeffersonGoncalves\ScannerGuard;

use Illuminate\Contracts\Cache\Repository;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardBan;
use JeffersonGoncalves\VisitorFingerprint\Support\IpAnonymizer;

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
