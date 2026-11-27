<?php

declare(strict_types=1);

namespace JeffersonGoncalves\ScannerGuard\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * A diagnosis of one IP asked of one agent (scanner-guard-agent 2.8.0+): the
 * agent gets it in its next pull, runs `diagnose`, and posts the report back.
 *
 * @property int $id
 * @property string $source
 * @property string $ip
 * @property int $capture seconds of tcpdump, 0 = none
 * @property string|null $report
 * @property Carbon|null $sent_at
 * @property Carbon|null $completed_at
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 */
class ScannerGuardAgentDiagnosis extends Model
{
    public const MAX_CAPTURE = 120;

    /** Seconds before a request the agent got but never answered is sent again. */
    public const RESEND_AFTER = 600;

    /** Seconds before an unanswered request stops being sent (an agent that is down). */
    public const EXPIRE_AFTER = 3600;

    protected $table = 'scanner_guard_agent_diagnostics';

    protected $fillable = [
        'source',
        'ip',
        'capture',
        'report',
        'sent_at',
        'completed_at',
    ];

    protected function casts(): array
    {
        return [
            'ip' => 'encrypted',
            'capture' => 'integer',
            'report' => 'encrypted',
            'sent_at' => 'datetime',
            'completed_at' => 'datetime',
        ];
    }

    /**
     * Not answered yet, and still worth sending to the agent.
     *
     * @param  Builder<self>  $query
     * @return Builder<self>
     */
    public function scopeDue(Builder $query): Builder
    {
        return $query
            ->whereNull('completed_at')
            ->where('created_at', '>', now()->subSeconds(static::EXPIRE_AFTER))
            ->where(fn (Builder $q) => $q->whereNull('sent_at')->orWhere('sent_at', '<=', now()->subSeconds(static::RESEND_AFTER)));
    }

    public function status(): string
    {
        return match (true) {
            $this->completed_at !== null => 'done',
            $this->created_at?->lte(now()->subSeconds(static::EXPIRE_AFTER)) ?? false => 'expired',
            $this->sent_at !== null => 'running',
            default => 'waiting',
        };
    }
}
