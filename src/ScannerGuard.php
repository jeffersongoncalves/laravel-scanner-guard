<?php

declare(strict_types=1);

namespace JeffersonGoncalves\ScannerGuard;

use Carbon\CarbonInterface;
use Carbon\CarbonPeriod;
use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Client\Response;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use InvalidArgumentException;
use JeffersonGoncalves\ScannerGuard\Contracts\DenylistSink;
use JeffersonGoncalves\ScannerGuard\Events\AgentEventRecorded;
use JeffersonGoncalves\ScannerGuard\Jobs\SyncDenylist;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardAgentDiagnosis;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardAgentEvent;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardAgentMetric;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardAgentNginxRule;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardAgentRule;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardBan;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardBlocklistEntry;
use JeffersonGoncalves\VisitorFingerprint\Support\IpAnonymizer;
use RuntimeException;
use Symfony\Component\HttpFoundation\IpUtils;
use Throwable;

/**
 * Core ban/hit-counting logic, shared by the middleware and the export
 * command. Every cache key is keyed by the salted IP hash rather than the
 * raw IP, EXCEPT the deliberate "raw-ip" entry written at ban time, whose
 * whole purpose is to let scanner-guard:sync-denylist hand a real IP to the
 * denylist sinks — see the README's "Privacy tradeoff" section.
 */
class ScannerGuard
{
    /** Whether the add_evidence migration ran, checked once per process. */
    protected ?bool $hasEvidenceColumn = null;

    /** @var array<class-string, bool> see hasTable() */
    protected array $tables = [];

    public function cache(): Repository
    {
        return Cache::store(config('scanner-guard.store'));
    }

    public function hashIp(string $ip): string
    {
        return IpAnonymizer::hash($ip);
    }

    /**
     * hashIp() hashes the text as-is and web servers report IPv6 compressed
     * ("2001:db8::1"), so a typed "2001:0db8::0001" must be compressed too or
     * its ban never matches. Not an IP: returned unchanged.
     */
    public function canonicalIp(string $ip): string
    {
        $packed = @inet_pton($ip);

        return $packed === false ? $ip : (string) inet_ntop($packed);
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
    public function sign(string $timestamp, string $body, ?string $secret = null): string
    {
        return hash_hmac('sha256', $timestamp.$body, $secret ?? (string) config('scanner-guard.http.secret'));
    }

    /**
     * HMAC of a denylist response. Bound to the request it answers (its
     * signature and source), so an older list can't be replayed; the fields
     * are newline-separated because source is free text and a header value
     * never holds a newline. The "response" prefix keeps it from ever being
     * a valid request signature (those start with the timestamp's digits).
     */
    public function signResponse(string $timestamp, string $requestSignature, string $source, string $body, ?string $secret = null): string
    {
        return hash_hmac('sha256', implode("\n", ['response', $timestamp, $requestSignature, $source, $body]), $secret ?? (string) config('scanner-guard.http.secret'));
    }

    /**
     * Receiving side: a source listed in http.secrets must be signed with its
     * own secret, so one satellite can't forward bans under another's name.
     * Any other source falls back to the shared http.secret.
     */
    public function secretFor(mixed $source): string
    {
        $secrets = (array) config('scanner-guard.http.secrets', []);

        return (string) (is_string($source) && array_key_exists($source, $secrets)
            ? $secrets[$source]
            : config('scanner-guard.http.secret'));
    }

    /**
     * This satellite's name in forwarded bans and denylist pulls.
     */
    public function source(): string
    {
        return (string) (config('scanner-guard.http.source') ?? config('app.name'));
    }

    /**
     * Central side of the pull: active bans whose raw IP is still cached (one
     * per IP, latest expiry) plus the static lists.
     *
     * With the source asking (an agent's pull), it also carries what is meant for
     * that agent: its optional nginx rules and the diagnoses waiting for it.
     *
     * @return array{bans: list<array{ip: string, reason: string, expires_at: string}>, ip_blocklist: list<string>, user_agent_patterns: list<string>, ignore: list<string>, agent_rules?: object, nginx_rules?: list<string>, diagnostics?: list<array{id: int, ip: string, capture: int}>}
     */
    public function denylist(?string $source = null): array
    {
        $bans = [];
        $ignore = $this->ipIgnore();

        foreach (ScannerGuardBan::query()->active()->orderByDesc('expires_at')->orderBy('id')->get() as $ban) {
            $ip = $this->rawIpForBan($ban);

            if ($ip !== null && ! IpUtils::checkIp($ip, $ignore)) {
                $bans[$ip] ??= ['ip' => $ip, 'reason' => $ban->reason, 'expires_at' => $ban->expires_at->toIso8601String()];
            }
        }

        $denylist = [
            'bans' => array_values($bans),
            'ip_blocklist' => $this->ipBlocklist(),
            'user_agent_patterns' => $this->userAgentPatterns(),
            'ignore' => $ignore,
        ];

        // Absent until the agent_rules migration ran: agents then keep what they have.
        $rules = $this->agentRules();

        if ($rules !== null) {
            // An object even when empty: agents read a JSON object, and [] would not be one.
            $denylist['agent_rules'] = (object) $rules;
        }

        if ($source === null) {
            return $denylist;
        }

        // Absent until each migration ran: agents then keep what they have.
        if ($this->hasTable(ScannerGuardAgentNginxRule::class)) {
            $denylist['nginx_rules'] = ScannerGuardAgentNginxRule::query()->orderBy('name')->get()
                ->filter(fn (ScannerGuardAgentNginxRule $rule): bool => $rule->appliesTo($source))
                ->pluck('name')->values()->all();
        }

        if ($this->hasTable(ScannerGuardAgentDiagnosis::class)) {
            $denylist['diagnostics'] = $this->dueDiagnoses($source);
        }

        return $denylist;
    }

    /**
     * The diagnoses waiting for source, marked as sent.
     *
     * @return list<array{id: int, ip: string, capture: int}>
     */
    protected function dueDiagnoses(string $source): array
    {
        $due = ScannerGuardAgentDiagnosis::query()->due()->where('source', $source)->orderBy('id')->get();

        if ($due->isNotEmpty()) {
            ScannerGuardAgentDiagnosis::query()->whereKey($due->modelKeys())->update(['sent_at' => now()]);
        }

        return $due->map(fn (ScannerGuardAgentDiagnosis $d): array => ['id' => $d->id, 'ip' => $d->ip, 'capture' => $d->capture])->values()->all();
    }

    /**
     * Asks each source's agent for a diagnosis of ip (scanner-guard-agent
     * diagnose), with a tcpdump capture of $capture seconds. The agents pick it
     * up in their next pull and post the report back.
     *
     * @param  list<string>  $sources
     * @return Collection<int, ScannerGuardAgentDiagnosis>
     */
    public function requestDiagnosis(string $ip, array $sources, int $capture = 0): Collection
    {
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            throw new InvalidArgumentException("Not an IP address: {$ip}");
        }

        if ($capture < 0 || $capture > ScannerGuardAgentDiagnosis::MAX_CAPTURE) {
            throw new InvalidArgumentException('The capture must be 0 to '.ScannerGuardAgentDiagnosis::MAX_CAPTURE.' seconds.');
        }

        return collect(array_values(array_unique($sources)))->map(fn (string $source): ScannerGuardAgentDiagnosis => ScannerGuardAgentDiagnosis::query()->create([
            'source' => $source,
            'ip' => $this->canonicalIp($ip),
            'capture' => $capture,
        ]));
    }

    /**
     * Stores the report an agent sent for one of its diagnoses. False when no
     * open diagnosis of that source has the id.
     */
    public function recordDiagnosis(string $source, int $id, string $report): bool
    {
        return ScannerGuardAgentDiagnosis::query()
            ->whereKey($id)
            ->where('source', $source)
            ->whereNull('completed_at')
            ->first()
            ?->update(['report' => $report, 'completed_at' => now()]) ?? false;
    }

    /**
     * Rule settings for scanner-guard-agent, keyed by rule name; rows out of
     * range are left out (the agents keep their own). Null without the table.
     *
     * @return array<string, array{threshold: int, window: int, ban: list<int>}>|null
     */
    public function agentRules(): ?array
    {
        // ponytail: one schema query per pull; agents pull once a minute each.
        if (! rescue(fn (): bool => Schema::hasTable((new ScannerGuardAgentRule)->getTable()), false, report: false)) {
            return null;
        }

        $rules = [];

        foreach (ScannerGuardAgentRule::query()->orderBy('name')->get() as $rule) {
            $payload = $rule->toAgentPayload();

            if ($payload === null) {
                Log::warning('scanner-guard: skipped invalid agent rule', ['name' => $rule->name]);

                continue;
            }

            $rules[$rule->name] = $payload;
        }

        return $rules;
    }

    /**
     * Aborts with 403 unless the request carries a valid agent signature (fresh
     * timestamp, HMAC of the body with the claimed source's secret). Returns the
     * signature, for the nonce check once the payload validates.
     */
    public function verifyAgentRequest(Request $request): string
    {
        $timestamp = (string) $request->header('X-Timestamp');
        $signature = (string) $request->header('X-Signature');
        $tolerance = (int) config('scanner-guard.http.tolerance', 300);
        $secret = $this->secretFor($request->json('source'));

        abort_unless(
            filled($secret)
                && ctype_digit($timestamp)
                && abs(now()->timestamp - (int) $timestamp) <= $tolerance
                && hash_equals($this->sign($timestamp, $request->getContent(), $secret), $signature),
            403
        );

        return $signature;
    }

    /**
     * Stores an event of a scanner-guard-agent report rule and fires
     * AgentEventRecorded. Null without the table (migration not run).
     *
     * @param  array<string, string>  $fields
     */
    public function recordAgentEvent(string $source, string $rule, string $ip, ?string $pattern, array $fields, ?string $line, bool $ignored, CarbonInterface $at): ?ScannerGuardAgentEvent
    {
        if (! $this->hasTable(ScannerGuardAgentEvent::class)) {
            return null;
        }

        $ipHash = $this->hashIp($ip);
        $fingerprint = ScannerGuardAgentEvent::fingerprint($rule, $ipHash, $fields);
        $details = (bool) config('scanner-guard.store_details', false);

        $event = ScannerGuardAgentEvent::query()->create([
            'source' => $source,
            'rule' => $rule,
            'ip_hash' => $ipHash,
            'ip' => $details ? $ip : null,
            'pattern' => $pattern,
            'fields' => $fields,
            'line' => $details ? $line : null,
            'ignored' => $ignored,
            'fingerprint' => $fingerprint,
            'first_seen' => ! ScannerGuardAgentEvent::query()->where('fingerprint', $fingerprint)->exists(),
            'occurred_at' => $at,
        ]);

        AgentEventRecorded::dispatch($event);

        return $event;
    }

    /**
     * Adds a heartbeat's matches (per rule) to the current hour of its source.
     * Nothing without the table.
     *
     * @param  array<string, int>  $matches
     */
    public function recordAgentMatches(string $source, array $matches): void
    {
        $matches = array_filter($matches, fn (int $n): bool => $n > 0);

        if ($matches === [] || ! $this->hasTable(ScannerGuardAgentMetric::class)) {
            return;
        }

        $hour = now()->startOfHour();

        foreach ($matches as $rule => $n) {
            $key = ['source' => $source, 'rule' => (string) $rule, 'hour' => $hour];

            // ponytail: update-then-insert; one heartbeat a minute per source never races itself.
            if (ScannerGuardAgentMetric::query()->where($key)->increment('matches', $n) === 0) {
                ScannerGuardAgentMetric::query()->create($key + ['matches' => $n]);
            }
        }
    }

    /**
     * Whether a model's table exists (its migration ran), checked once per process.
     *
     * @param  class-string<Model>  $model
     */
    public function hasTable(string $model): bool
    {
        return $this->tables[$model] ??= rescue(fn (): bool => Schema::hasTable((new $model)->getTable()), false, report: false);
    }

    /**
     * What every DenylistSink receives: valid ip_blocklist entries first (they
     * win over a ban of the same IP), then one entry per banned IP whose raw
     * IP is still cached, latest expiry first. Database bans with the
     * "database" driver, the last pull with "http", nothing else otherwise.
     * Ignored IPs are left out; a blocklist range that merely contains one is
     * not, a sink can't hold the exception.
     *
     * @return list<array{ip: string, reason: string, expires_at: string|null}>
     */
    public function denylistEntries(): array
    {
        $entries = [];
        $ignore = $this->ipIgnore();

        foreach ($this->ipBlocklist() as $range) {
            if (! $this->isValidRange($range)) {
                // Passed on as-is, a bad entry would break the sink (e.g. fail `nginx -t`).
                Log::warning('scanner-guard: skipped invalid ip_blocklist entry', ['entry' => $range]);

                continue;
            }

            if (! str_contains($range, '/') && IpUtils::checkIp($range, $ignore)) {
                continue;
            }

            $entries[$range] = ['ip' => $range, 'reason' => 'static', 'expires_at' => null];
        }

        // An escalated IP keeps several active rows; the first one seen per IP
        // (latest expiry, id breaking ties) is the one passed on.
        $bans = match ($this->driver()) {
            'database' => ScannerGuardBan::query()->active()->orderByDesc('expires_at')->orderBy('id')->get()
                ->map(fn (ScannerGuardBan $ban): array => ['ip' => $this->rawIpForBan($ban), 'reason' => $ban->reason, 'expires_at' => $ban->expires_at->toIso8601String()])
                ->all(),
            'http' => collect($this->pulledBans())->map(fn (array $ban, string $hash): array => ['ip' => $this->rawIpFor($hash)] + $ban)->values()->all(),
            default => [],
        };

        foreach ($bans as $ban) {
            $ip = $ban['ip'];

            if ($ip !== null && ! IpUtils::checkIp($ip, $ignore)) {
                // A forwarded or pulled reason is free text; sinks write it into config files,
                // where a newline would end their comment.
                $entries[$ip] ??= ['ip' => $ip, 'reason' => (string) preg_replace('/[^\w.-]/', '_', $ban['reason']), 'expires_at' => $ban['expires_at']];
            }
        }

        return array_values($entries);
    }

    /**
     * An IPv4/IPv6 address, optionally with a /prefix in range.
     */
    public function isValidRange(string $entry): bool
    {
        [$address, $prefix] = array_pad(explode('/', $entry, 2), 2, null);

        if (filter_var($address, FILTER_VALIDATE_IP) === false) {
            return false;
        }

        return $prefix === null
            || (ctype_digit($prefix) && (int) $prefix <= (str_contains((string) $address, ':') ? 128 : 32));
    }

    /**
     * @return list<DenylistSink>
     */
    public function sinks(): array
    {
        return array_values(array_map(
            fn (string $sink): DenylistSink => app($sink),
            (array) config('scanner-guard.sinks', []),
        ));
    }

    /**
     * Satellite side: fetches the central denylist and applies it. Throws on
     * a failed request or a bad signature, leaving the last pulled list in place.
     */
    public function pullDenylist(): void
    {
        $source = $this->source();
        $timestamp = (string) now()->timestamp;
        $signature = $this->sign($timestamp, $source);

        $response = Http::timeout((int) config('scanner-guard.http.timeout', 2))
            ->acceptJson()
            ->withHeaders(['X-Source' => $source, 'X-Timestamp' => $timestamp, 'X-Signature' => $signature])
            ->get((string) config('scanner-guard.http.url'))
            ->throw();

        $this->verifyResponse($response, $signature, $source);

        $data = $response->json();
        $this->applyDenylist(is_array($data) ? $data : []);
    }

    /**
     * An unsigned response (a central app older than signed responses) passes
     * unless http.require_signed_response is on; a bad signature never does.
     */
    protected function verifyResponse(Response $response, string $requestSignature, string $source): void
    {
        $timestamp = $response->header('X-Timestamp');
        $signature = $response->header('X-Signature');

        if ($signature === '' && ! config('scanner-guard.http.require_signed_response', false)) {
            return;
        }

        if (! ctype_digit($timestamp)
            || abs(now()->timestamp - (int) $timestamp) > (int) config('scanner-guard.http.tolerance', 300)
            || ! hash_equals($this->signResponse($timestamp, $requestSignature, $source, $response->body()), $signature)) {
            throw new RuntimeException($signature === '' ? 'The central denylist response is not signed.' : 'The central denylist response has an invalid signature.');
        }
    }

    /**
     * Caches each pulled ban until its expiry, so isBanned() blocks it, and
     * lifts the ones the central app no longer lists (unbanned there). Bans
     * made here and not pulled yet are left alone.
     *
     * @param  array<mixed>  $data
     */
    public function applyDenylist(array $data): void
    {
        $previous = (array) $this->cache()->get($this->pulledBansKey(), []);
        $pulled = [];

        foreach ((array) ($data['bans'] ?? []) as $ban) {
            $ip = is_array($ban) ? ($ban['ip'] ?? null) : null;

            if (! is_string($ip) || filter_var($ip, FILTER_VALIDATE_IP) === false) {
                continue;
            }

            try {
                $expiresAt = Carbon::parse((string) ($ban['expires_at'] ?? ''));
            } catch (Throwable) {
                continue;
            }

            if ($expiresAt->isPast()) {
                continue;
            }

            $this->cacheBan($ip, $expiresAt);
            $pulled[$this->hashIp($ip)] = ['reason' => (string) ($ban['reason'] ?? ''), 'expires_at' => $expiresAt->toIso8601String()];
        }

        foreach (array_keys(array_diff_key($previous, $pulled)) as $hash) {
            $this->cache()->forget($this->banKey((string) $hash));
            $this->cache()->forget($this->rawIpKey((string) $hash));
        }

        $strings = fn (mixed $list): array => array_values(array_filter((array) $list, 'is_string'));

        // Absent: a central app older than the ignore list, keep the last one. An empty list is a list.
        $ignore = array_key_exists('ignore', $data)
            ? $strings($data['ignore'])
            : ($this->pulledBlocklist()[ScannerGuardBlocklistEntry::TYPE_IGNORE] ?? []);

        // Forever: an unreachable central app must not lift the last known list.
        $this->cache()->forever($this->pulledBansKey(), $pulled);
        $this->cache()->forever($this->pulledBlocklistKey(), [
            ScannerGuardBlocklistEntry::TYPE_IP => $strings($data['ip_blocklist'] ?? []),
            ScannerGuardBlocklistEntry::TYPE_USER_AGENT => $strings($data['user_agent_patterns'] ?? []),
            ScannerGuardBlocklistEntry::TYPE_IGNORE => $ignore,
        ]);
    }

    /**
     * Active pulled bans, for the satellite's denylist sinks.
     *
     * @return array<string, array{reason: string, expires_at: string}> keyed by ip_hash
     */
    public function pulledBans(): array
    {
        return array_filter(
            (array) $this->cache()->get($this->pulledBansKey(), []),
            fn (array $ban): bool => Carbon::parse($ban['expires_at'])->isFuture(),
        );
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
     * Never blocked or banned, see ipIgnore().
     */
    public function isIpIgnored(string $ip): bool
    {
        $ignore = $this->ipIgnore();

        return $ignore !== [] && IpUtils::checkIp($ip, $ignore);
    }

    /**
     * Config ip_ignore plus the database "ignore" entries. Invalid entries
     * are dropped, and so are ranges wide enough to exempt much of the
     * internet (a stray 0.0.0.0/0 would turn the package off).
     *
     * @return list<string>
     */
    public function ipIgnore(): array
    {
        return array_values(array_filter(
            $this->mergeBlocklist((array) config('scanner-guard.ip_ignore', []), ScannerGuardBlocklistEntry::TYPE_IGNORE),
            function (string $entry): bool {
                $prefix = explode('/', $entry, 2)[1] ?? null;

                return $this->isValidRange($entry)
                    && ($prefix === null || (int) $prefix >= (str_contains($entry, ':') ? 16 : 8));
            },
        ));
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
     * Drops the cached database blocklist and re-syncs the denylist sinks.
     * Called by ScannerGuardBlocklistEntry on save/delete.
     */
    public function blocklistChanged(): void
    {
        // A new version, not a forget(): a read still in flight from before the
        // change can only fill the old version's key, never the current one.
        $this->cache()->forever($this->blocklistVersionKey(), Str::random(16));
        $this->queueSync();
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
        $claims = [$this->banningKey($ipHash)];
        $deleted = 0;

        if ($this->driver() === 'database') {
            $bans = ScannerGuardBan::query()->where('ip_hash', $ipHash)->active();

            // Whole rows: without the add_source migration there is no such column to select.
            foreach ((clone $bans)->get() as $ban) {
                $claims[] = $this->banningKey($ipHash, $ban->getAttributes()['source'] ?? null);
            }

            $deleted = $bans->delete();
        }

        $this->cache()->forget($this->banKey($ipHash));
        $this->cache()->forget($this->rawIpKey($ipHash));
        // So a manual unban doesn't swallow a fresh ban of the same IP right after.
        foreach (array_unique($claims) as $claim) {
            $this->cache()->forget($claim);
        }

        $this->queueSync();

        return (int) $deleted;
    }

    /**
     * @param  array<mixed>  $configured
     * @return list<string>
     */
    protected function mergeBlocklist(array $configured, string $type): array
    {
        return array_values(array_unique(array_map('strval', [
            ...$configured,
            ...($this->databaseBlocklist()[$type] ?? []),
            ...($this->pulledBlocklist()[$type] ?? []),
        ])));
    }

    /**
     * The central app's static lists, from the last pull (http driver only).
     *
     * @return array<string, list<string>>
     */
    protected function pulledBlocklist(): array
    {
        return $this->driver() === 'http' ? (array) $this->cache()->get($this->pulledBlocklistKey(), []) : [];
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
     * @return ScannerGuardBan|null the audit row, or null when the driver isn't "database", the IP is
     *                              ignored or another request of the same burst already banned it
     */
    public function ban(string $ip, string $reason, string $matchedValue, int $hitCount, ?string $path = null): ?ScannerGuardBan
    {
        if ($this->isIpIgnored($ip)) {
            return null;
        }

        $claim = $this->banningKey($this->hashIp($ip));

        if (! $this->claimBan($claim)) {
            return null;
        }

        return $this->releaseClaimOnFailure($claim, fn (): ?ScannerGuardBan => $this->applyBan($ip, $reason, $matchedValue, $hitCount, $this->cleanPath($path)));
    }

    protected function applyBan(string $ip, string $reason, string $matchedValue, int $hitCount, ?string $path): ?ScannerGuardBan
    {
        $bannedAt = now();
        $offense = $this->nextOffense($this->hashIp($ip), $reason);
        $expiresAt = $bannedAt->copy()->addSeconds($this->banDuration($offense));

        // Resolved before any cache write, so a bad driver fails without a half-applied ban.
        $persist = match ($this->driver()) {
            'database' => fn (): ScannerGuardBan => $this->storeBan($ip, $reason, $matchedValue, $hitCount, $bannedAt, $expiresAt, $offense, path: $path),
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
                'source' => $this->source(),
            ]),
            'cache' => fn () => null,
            default => throw new InvalidArgumentException("Unsupported scanner-guard driver [{$this->driver()}]."),
        };

        if ($this->driver() !== 'database') {
            $this->cacheBan($ip, $expiresAt); // storeBan() caches under its lock
        }

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
     * satellite app exactly like a local one (including store_details).
     * Null when the IP is ignored, or the same source already forwarded it
     * moments ago (e.g. replicas behind a load balancer sharing a source). Every other source
     * gets its own row, so an incident shows each server it hit.
     *
     * @param  list<string>|null  $evidence  log lines a scanner-guard-agent banned on, stored with store_details
     */
    public function recordForwardedBan(string $ip, string $reason, string $matchedValue, int $hitCount, CarbonInterface $bannedAt, CarbonInterface $expiresAt, ?int $offense = null, ?string $source = null, ?string $path = null, ?array $evidence = null): ?ScannerGuardBan
    {
        if ($this->isIpIgnored($ip)) {
            return null;
        }

        $claim = $this->banningKey($this->hashIp($ip), $source);

        // The satellite chose the expiry, so this app's own durations don't bound it.
        if (! $this->claimBan($claim, $expiresAt->getTimestamp() - now()->getTimestamp())) {
            return null;
        }

        return $this->releaseClaimOnFailure($claim, fn (): ScannerGuardBan => $this->storeBan($ip, $reason, $matchedValue, $hitCount, $bannedAt, $expiresAt, $offense, $source, $this->cleanPath($path), $evidence));
    }

    /**
     * Concurrent requests of one burst all pass isBanned() before the first
     * ban is cached, and each would store its own row with a climbing
     * offense. add() is atomic: only the first caller wins.
     */
    protected function claimBan(string $claim, int $banSeconds = 60): bool
    {
        // 60s outlives a burst; capped by the shortest ban so the guard never outlives a ban.
        $ttl = min(60, $banSeconds, (int) config('scanner-guard.ban_duration', 86400), ...array_map('intval', (array) config('scanner-guard.escalation', [])));

        return $this->cache()->add($claim, true, max($ttl, 1));
    }

    /**
     * A ban that throws before it is stored must not keep the claim, or every
     * retry for that IP would be dropped until it expires.
     *
     * @template T
     *
     * @param  callable(): T  $work
     * @return T
     */
    protected function releaseClaimOnFailure(string $claim, callable $work): mixed
    {
        try {
            return $work();
        } catch (Throwable $e) {
            $this->cache()->forget($claim);

            throw $e;
        }
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
     * The raw IP of a ban row: the cached one, or else the IP the row stored
     * itself (store_details), cached back until the ban expires. Without it a
     * cache flush would drop every older ban from the denylist and the sinks.
     * Null when neither is there, or the stored IP can't be decrypted (a key
     * missing from APP_PREVIOUS_KEYS) or doesn't match the row's hash.
     */
    public function rawIpForBan(ScannerGuardBan $ban): ?string
    {
        $ip = $this->rawIpFor($ban->ip_hash);

        if ($ip !== null) {
            return $ip;
        }

        $ip = rescue(fn (): mixed => $ban->ip, null, report: false);

        if (! is_string($ip) || filter_var($ip, FILTER_VALIDATE_IP) === false || ! hash_equals($ban->ip_hash, $this->hashIp($ip))) {
            return null;
        }

        // add(), not put(): a newer, longer ban cached meanwhile keeps its own expiry.
        $this->cache()->add($this->rawIpKey($ban->ip_hash), $ip, $ban->expires_at);

        return $ip;
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
     * A banned IP seen again whose raw IP is gone from the cache (a flush, an
     * eviction) gets it cached back until its ban expires, and the sinks are
     * re-synced, so the ban reaches them again. Database driver only: an http
     * satellite gets raw IPs from the pull, and the cache driver loses the
     * ban together with its raw IP. At most one lookup a minute per IP, so a
     * scanner hammering the app can't turn a missing row into a query storm.
     */
    public function recoverRawIp(string $ip): void
    {
        if ($this->driver() !== 'database') {
            return;
        }

        $hash = $this->hashIp($ip);

        if ($this->cache()->has($this->rawIpKey($hash)) || ! $this->cache()->add($this->rawIpCheckKey($hash), true, 60)) {
            return;
        }

        try {
            $ban = ScannerGuardBan::query()->where('ip_hash', $hash)->active()->latest('expires_at')->first();
        } catch (Throwable $e) {
            // Best effort: a database outage must not turn the banned response into a 500.
            report($e);

            return;
        }

        // add(), not put(): a ban stored meanwhile (e.g. escalated, longer) keeps its own expiry.
        if ($ban !== null && $this->cache()->add($this->rawIpKey($hash), $ip, $ban->expires_at)) {
            $this->queueSync();
        }
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
        // Deliberately where a raw IP is cached (recoverRawIp() re-caches a
        // lost one) — required so scanner-guard:sync-denylist can hand sinks a real IP.
        // See README for why the sinks don't read it from the database row.
        $this->cache()->put($this->rawIpKey($hash), $ip, $expiresAt);
    }

    /**
     * @param  list<string>|null  $evidence
     */
    protected function storeBan(string $ip, string $reason, string $matchedValue, int $hitCount, CarbonInterface $bannedAt, CarbonInterface $expiresAt, ?int $offense = null, ?string $source = null, ?string $path = null, ?array $evidence = null): ScannerGuardBan
    {
        $details = (bool) config('scanner-guard.store_details', false);

        // offense/source/ip/path/evidence only when set, so apps that never ran the matching add_* migrations keep working.
        $attributes = array_filter([
            'ip_hash' => $this->hashIp($ip),
            'reason' => $reason,
            'matched_value' => $matchedValue,
            'hit_count' => $hitCount,
            'banned_at' => $bannedAt,
            'expires_at' => $expiresAt,
            'offense' => $offense,
            'source' => $source,
            'ip' => $details ? $ip : null,
            'path' => $details ? $path : null,
            // Agents may be upgraded before the central app runs the migration: never let it cost the ban.
            'evidence' => $details && $evidence && $this->hasEvidenceColumn() ? $evidence : null,
        ], fn ($value) => $value !== null);

        $ban = $this->withBanLock($attributes['ip_hash'], function () use ($attributes, $ip, $expiresAt): ScannerGuardBan {
            // A shorter ban from one source must not cut another's longer one short in the cache.
            // rescue(): a failed lookup must not keep this ban out of the cache.
            $latest = rescue(fn (): ?ScannerGuardBan => ScannerGuardBan::query()->where('ip_hash', $attributes['ip_hash'])->active()->latest('expires_at')->first());
            $this->cacheBan($ip, $latest !== null && $latest->expires_at->gt($expiresAt) ? $latest->expires_at : $expiresAt);

            return ScannerGuardBan::query()->create($attributes);
        });

        $this->recordDailyStats($ban);

        if (config('scanner-guard.sync_on_ban', true)) {
            $this->queueSync();
        }

        return $ban;
    }

    // ponytail: cached for the process, so a long-running worker sees the migration after its next restart.
    protected function hasEvidenceColumn(): bool
    {
        return $this->hasEvidenceColumn ??= rescue(
            fn (): bool => Schema::hasColumn((new ScannerGuardBan)->getTable(), 'evidence'),
            false,
            report: false,
        );
    }

    /**
     * Serializes read + cache + insert of one IP's bans, so whichever runs
     * second sees the first one's row. Short work only (no stats or sync in
     * here). Fails open: without a lock the ban is still stored.
     *
     * @template T
     *
     * @param  callable(): T  $work
     * @return T
     */
    protected function withBanLock(string $hash, callable $work): mixed
    {
        $store = $this->cache()->getStore();
        $lock = $store instanceof LockProvider ? $store->lock($this->banLockKey($hash), 10) : null;

        try {
            $lock?->block(3);
        } catch (Throwable $e) {
            report($e);
            $lock = null;
        }

        try {
            return $work();
        } finally {
            $lock?->release();
        }
    }

    /**
     * Keeps the sinks within seconds of the ban table and blocklist instead
     * of a minute behind. A queue failure is logged, never breaks the ban,
     * unban or blocklist change.
     */
    protected function queueSync(): void
    {
        if ((array) config('scanner-guard.sinks', []) === []) {
            return;
        }

        try {
            SyncDenylist::dispatch();
        } catch (Throwable $e) {
            Log::error('scanner-guard: failed to queue denylist sync', ['exception' => $e->getMessage()]);
        }
    }

    /**
     * Deferred until after the response is sent, so the remote call never
     * slows down or fails the request; failures are only logged. The raw IP
     * is sent (the central app needs it for its denylist sinks) but its own
     * salt hashes it — a satellite's ip_hash wouldn't match there.
     * always(): the banning request itself answers 404, and Laravel skips
     * deferred callbacks on a >= 400 response.
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
        })->always();

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

    protected function banningKey(string $hash, ?string $source = null): string
    {
        return "scanner-guard:banning:{$hash}".($source === null ? '' : ':'.md5($source));
    }

    protected function banLockKey(string $hash): string
    {
        return "scanner-guard:ban-lock:{$hash}";
    }

    /**
     * Attacker-controlled: raw bytes or NULs would fail the insert (or the
     * JSON encoding of a forwarded ban) and so lose the ban record itself.
     * A satellite may also send a query string, which is never kept.
     */
    protected function cleanPath(?string $path): ?string
    {
        if ($path === null) {
            return null;
        }

        $path = str_replace("\0", '', Str::before($path, '?'));

        // Percent-encoded, not mb_scrub(): its "?" would read as a query string on the central app.
        if (! mb_check_encoding($path, 'UTF-8')) {
            $path = (string) preg_replace_callback('/[\x80-\xFF]/', fn (array $byte): string => rawurlencode($byte[0]), $path);
        }

        return mb_substr($path, 0, 2048, 'UTF-8');
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

    protected function rawIpCheckKey(string $hash): string
    {
        return "scanner-guard:raw-ip-check:{$hash}";
    }

    protected function blocklistKey(string $version): string
    {
        return "scanner-guard:blocklist:{$version}";
    }

    protected function blocklistVersionKey(): string
    {
        return 'scanner-guard:blocklist-version';
    }

    protected function pulledBansKey(): string
    {
        return 'scanner-guard:pulled-bans';
    }

    protected function pulledBlocklistKey(): string
    {
        return 'scanner-guard:pulled-blocklist';
    }
}
