<?php

declare(strict_types=1);

namespace JeffersonGoncalves\ScannerGuard\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * Something a scanner-guard-agent report rule saw (an accepted SSH login, say):
 * not a ban, news. The agent sends the same event (rule, IP, fields) at most
 * once a day; first_seen marks the first time this app ever got it.
 *
 * @property int $id
 * @property string $source
 * @property string $rule
 * @property string $ip_hash
 * @property string|null $ip decrypted IP, null unless scanner-guard.store_details was on
 * @property string|null $pattern
 * @property array<string, string>|null $fields
 * @property string|null $line the log line, IP replaced by <ip>; null unless store_details was on
 * @property bool $ignored the IP is on an ignore list
 * @property string $fingerprint
 * @property bool $first_seen
 * @property Carbon $occurred_at
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 */
class ScannerGuardAgentEvent extends Model
{
    protected $table = 'scanner_guard_agent_events';

    protected $fillable = [
        'source',
        'rule',
        'ip_hash',
        'ip',
        'pattern',
        'fields',
        'line',
        'ignored',
        'fingerprint',
        'first_seen',
        'occurred_at',
    ];

    protected $hidden = ['ip', 'line'];

    protected function casts(): array
    {
        return [
            'ip' => 'encrypted',
            'fields' => 'array',
            'line' => 'encrypted',
            'ignored' => 'boolean',
            'first_seen' => 'boolean',
            'occurred_at' => 'datetime',
        ];
    }

    /**
     * @param  array<string, string>  $fields
     */
    public static function fingerprint(string $rule, string $ipHash, array $fields): string
    {
        ksort($fields);

        return hash('sha256', $rule."\0".$ipHash."\0".json_encode($fields, JSON_THROW_ON_ERROR));
    }
}
