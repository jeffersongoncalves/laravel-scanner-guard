<?php

declare(strict_types=1);

namespace JeffersonGoncalves\ScannerGuard\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * A server agent (scanner-guard-agent) as last reported by its heartbeat.
 * One row per source, updated on every heartbeat.
 *
 * @property int $id
 * @property string $source
 * @property string|null $version
 * @property string|null $os
 * @property list<string>|null $addresses
 * @property list<string>|null $rules
 * @property int $active_bans
 * @property Carbon|null $started_at
 * @property Carbon $last_seen_at
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 */
class ScannerGuardAgent extends Model
{
    /** Seconds without a heartbeat before an agent counts as offline. */
    public const STALE_AFTER = 300;

    protected $table = 'scanner_guard_agents';

    protected $fillable = [
        'source',
        'version',
        'os',
        'addresses',
        'rules',
        'active_bans',
        'started_at',
        'last_seen_at',
    ];

    protected function casts(): array
    {
        return [
            'rules' => 'array',
            'addresses' => 'array',
            'active_bans' => 'integer',
            'started_at' => 'datetime',
            'last_seen_at' => 'datetime',
        ];
    }

    public function isOnline(int $staleAfter = self::STALE_AFTER): bool
    {
        return $this->last_seen_at->gt(now()->subSeconds($staleAfter));
    }

    /**
     * @param  Builder<self>  $query
     * @return Builder<self>
     */
    public function scopeOnline(Builder $query, int $staleAfter = self::STALE_AFTER): Builder
    {
        return $query->where('last_seen_at', '>', now()->subSeconds($staleAfter));
    }

    /**
     * @param  Builder<self>  $query
     * @return Builder<self>
     */
    public function scopeOffline(Builder $query, int $staleAfter = self::STALE_AFTER): Builder
    {
        return $query->where('last_seen_at', '<=', now()->subSeconds($staleAfter));
    }
}
