<?php

declare(strict_types=1);

namespace JeffersonGoncalves\ScannerGuard\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * Overrides the threshold, window and ban steps of every scanner-guard-agent
 * rule with this name, served with the denylist. The rule's patterns and log
 * source stay in each agent's agent.yaml. Durations are written like the
 * agent's: a number and s, m, h or d ("10m", "1d").
 *
 * @property int $id
 * @property string $name
 * @property int $threshold
 * @property string $window
 * @property string $ban comma-separated durations, one per offense ("1d, 7d, 30d")
 * @property Carbon|null $created_at
 * @property Carbon|null $updated_at
 */
class ScannerGuardAgentRule extends Model
{
    public const MAX_THRESHOLD = 10000;

    public const MAX_WINDOW = 30 * 86400;

    public const MAX_BAN = 365 * 86400;

    public const MAX_STEPS = 10;

    protected $table = 'scanner_guard_agent_rules';

    protected $fillable = [
        'name',
        'threshold',
        'window',
        'ban',
    ];

    protected function casts(): array
    {
        return [
            'threshold' => 'integer',
        ];
    }

    /**
     * Seconds, or null when $value isn't a positive number followed by s, m, h or d.
     */
    public static function parseDuration(string $value): ?int
    {
        if (! preg_match('/^\s*(\d{1,7})\s*([smhd])\s*$/', $value, $m) || (int) $m[1] === 0) {
            return null;
        }

        return (int) $m[1] * ['s' => 1, 'm' => 60, 'h' => 3600, 'd' => 86400][$m[2]];
    }

    /**
     * Seconds per step, or null unless every step parses and is at most MAX_BAN.
     *
     * @return list<int>|null
     */
    public static function parseSteps(string $value): ?array
    {
        $steps = [];

        foreach (explode(',', $value) as $step) {
            $seconds = static::parseDuration($step);

            if ($seconds === null || $seconds > static::MAX_BAN) {
                return null;
            }

            $steps[] = $seconds;
        }

        return count($steps) <= static::MAX_STEPS ? $steps : null;
    }

    /**
     * What the agents receive, in seconds; null when a value is out of range
     * (a row written around the panel's validation), so the agents keep their own.
     *
     * @return array{threshold: int, window: int, ban: list<int>}|null
     */
    public function toAgentPayload(): ?array
    {
        $window = static::parseDuration($this->window);
        $ban = static::parseSteps($this->ban);

        if ($this->threshold < 1 || $this->threshold > static::MAX_THRESHOLD || $window === null || $window > static::MAX_WINDOW || $ban === null) {
            return null;
        }

        return ['threshold' => $this->threshold, 'window' => $window, 'ban' => $ban];
    }
}
