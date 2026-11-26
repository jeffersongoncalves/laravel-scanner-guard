<?php

declare(strict_types=1);

namespace JeffersonGoncalves\ScannerGuard\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Casts\Attribute;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * Permanent audit trail of bans. `ip_hash` is a salted sha256 (see
 * JeffersonGoncalves\VisitorFingerprint\Support\IpAnonymizer::hash()). The
 * IP itself is only stored, encrypted, with `scanner-guard.store_details` on
 * (see README for the privacy tradeoff this implies).
 *
 * @property int $id
 * @property string $ip_hash
 * @property string $reason
 * @property string $matched_value
 * @property int $hit_count
 * @property Carbon $banned_at
 * @property Carbon $expires_at
 * @property int|null $offense escalation step (1 = first offense), null when the ban didn't escalate
 * @property string|null $source satellite app that forwarded the ban (http driver), null when banned locally
 * @property string|null $ip decrypted IP, null unless scanner-guard.store_details was on at ban time
 * @property string|null $path path (no query string) that triggered the ban, same condition; attacker-controlled, escape it
 * @property list<string>|null $evidence decrypted log lines a scanner-guard-agent banned on (its IP replaced by `<ip>`), same condition; attacker-controlled, escape it
 * @property-read bool $is_active
 *
 * @method static \Illuminate\Database\Eloquent\Builder<static> active()
 */
class ScannerGuardBan extends Model
{
    public const REASON_SCANNER_PATH = 'scanner_path';

    public const REASON_ASN = 'asn_blocklist';

    public const REASON_NOT_FOUND_FLOOD = 'not_found_flood';

    public const REASON_USER_AGENT = 'user_agent';

    public $timestamps = false;

    protected $fillable = [
        'ip_hash',
        'reason',
        'matched_value',
        'hit_count',
        'banned_at',
        'expires_at',
        'offense',
        'source',
        'ip',
        'path',
        'evidence',
    ];

    /** Read $ban->ip and $ban->evidence explicitly; toArray()/toJson() must not leak them by accident. */
    protected $hidden = ['ip', 'evidence'];

    protected $casts = [
        'ip' => 'encrypted',
        'evidence' => 'encrypted:array',
        'hit_count' => 'integer',
        'offense' => 'integer',
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
