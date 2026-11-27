<?php

declare(strict_types=1);

namespace JeffersonGoncalves\ScannerGuard\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * Matching log lines per agent (source), rule and hour, summed from the
 * heartbeats' matches: how much each server is attacked.
 *
 * @property int $id
 * @property string $source
 * @property string $rule
 * @property Carbon $hour start of the hour
 * @property int $matches
 */
class ScannerGuardAgentMetric extends Model
{
    public $timestamps = false;

    protected $table = 'scanner_guard_agent_metrics';

    protected $fillable = [
        'source',
        'rule',
        'hour',
        'matches',
    ];

    protected function casts(): array
    {
        return [
            'hour' => 'datetime',
            'matches' => 'integer',
        ];
    }
}
