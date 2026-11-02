<?php

declare(strict_types=1);

namespace JeffersonGoncalves\ScannerGuard\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use JeffersonGoncalves\ScannerGuard\ScannerGuard;

/**
 * A runtime blocklist entry, added on top of the config `ip_blocklist` /
 * `user_agent_blocklist.patterns` (database driver only). Saving or
 * deleting a model refreshes the cached list and re-exports nginx; a mass
 * query()->delete() / update() skips model events, so call
 * ScannerGuard::blocklistChanged() yourself after one.
 *
 * @property int $id
 * @property string $type
 * @property string $value
 * @property string|null $note
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 */
class ScannerGuardBlocklistEntry extends Model
{
    public const TYPE_IP = 'ip';

    public const TYPE_USER_AGENT = 'user_agent';

    protected $table = 'scanner_guard_blocklist';

    protected $fillable = [
        'type',
        'value',
        'note',
    ];

    protected static function booted(): void
    {
        // After commit: an earlier refresh could re-cache the old rows, and a rollback must not export.
        $changed = fn (self $entry) => $entry->getConnection()->afterCommit(fn () => app(ScannerGuard::class)->blocklistChanged());

        static::saved($changed);
        static::deleted($changed);
    }
}
