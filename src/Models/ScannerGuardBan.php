<?php

declare(strict_types=1);

namespace JeffersonGoncalves\ScannerGuard\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Casts\Attribute;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * Permanent audit trail of bans. `ip_hash` is a salted sha256 (see
 * JeffersonGoncalves\VisitorFingerprint\Support\IpAnonymizer::hash()) —
 * never the raw IP, by design (see README for the export-to-nginx tradeoff
 * this implies).
 *
 * @property int $id
 * @property string $ip_hash
 * @property string $reason
 * @property string $matched_value
 * @property int $hit_count
 * @property Carbon $banned_at
 * @property Carbon $expires_at
 * @property-read bool $is_active
 *
 * @method static \Illuminate\Database\Eloquent\Builder<static> active()
 */
class ScannerGuardBan extends Model
{
    public const REASON_SCANNER_PATH = 'scanner_path';

    public const REASON_ASN = 'asn_blocklist';

    public $timestamps = false;

    protected $fillable = [
        'ip_hash',
        'reason',
        'matched_value',
        'hit_count',
        'banned_at',
        'expires_at',
    ];

    protected $casts = [
        'hit_count' => 'integer',
        'banned_at' => 'datetime',
        'expires_at' => 'datetime',
    ];

    public function getTable(): string
    {
        return config('scanner-guard.table', 'scanner_guard_bans');
    }

    /**
     * @param  Builder<ScannerGuardBan>  $query
     * @return Builder<ScannerGuardBan>
     */
    protected function scopeActive(Builder $query): Builder
    {
        return $query->where('expires_at', '>', now());
    }

    protected function isActive(): Attribute
    {
        return Attribute::get(fn (): bool => $this->expires_at->isFuture());
    }
}
