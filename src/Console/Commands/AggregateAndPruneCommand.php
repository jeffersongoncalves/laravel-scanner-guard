<?php

declare(strict_types=1);

namespace JeffersonGoncalves\ScannerGuard\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardBan;

/**
 * Folds a day's expired bans into scanner_guard_ban_daily_stats, then prunes
 * ban rows past the configured retention window. Only ever touches bans
 * whose expires_at is already in the past — still-active bans are never
 * aggregated or pruned.
 */
class AggregateAndPruneCommand extends Command
{
    protected $signature = 'scanner-guard:aggregate-and-prune {--date= : Date to aggregate (Y-m-d), defaults to yesterday}';

    protected $description = 'Aggregate expired bans into scanner_guard_ban_daily_stats and prune old ban rows.';

    public function handle(): int
    {
        $date = $this->option('date') ? Carbon::parse((string) $this->option('date')) : Carbon::yesterday();

        $this->aggregate($date);
        $this->prune();

        return self::SUCCESS;
    }

    protected function aggregate(Carbon $date): void
    {
        $from = $date->copy()->startOfDay();
        $to = $date->copy()->endOfDay();

        $query = fn (): Builder => ScannerGuardBan::query()
            ->whereBetween('expires_at', [$from, $to])
            ->where('expires_at', '<=', now());

        DB::table(config('scanner-guard.daily_stats_table', 'scanner_guard_ban_daily_stats'))->updateOrInsert(
            ['date' => $date->toDateString()],
            [
                'bans_count' => $query()->count(),
                'hits_total' => (int) $query()->sum('hit_count'),
                'reason_stats' => json_encode($this->reasonStats($query())),
                'top_matched_values' => json_encode($this->topMatchedValues($query())),
                'updated_at' => now(),
            ]
        );
    }

    protected function prune(): void
    {
        ScannerGuardBan::query()
            ->where('expires_at', '<', now()->subDays((int) config('scanner-guard.retention_days', 90)))
            ->delete();
    }

    /**
     * @param  Builder<ScannerGuardBan>  $query
     * @return array<string, int>
     */
    protected function reasonStats(Builder $query): array
    {
        return $query
            ->groupBy('reason')
            ->selectRaw('reason as label, count(*) as aggregate')
            ->pluck('aggregate', 'label')
            ->map(fn ($count) => (int) $count)
            ->all();
    }

    /**
     * @param  Builder<ScannerGuardBan>  $query
     * @return array<string, int>
     */
    protected function topMatchedValues(Builder $query): array
    {
        return $query
            ->groupBy('matched_value')
            ->selectRaw('matched_value as label, sum(hit_count) as aggregate')
            ->orderByDesc('aggregate')
            ->limit(10)
            ->pluck('aggregate', 'label')
            ->map(fn ($count) => (int) $count)
            ->all();
    }
}
