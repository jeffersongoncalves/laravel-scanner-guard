<?php

declare(strict_types=1);

namespace JeffersonGoncalves\ScannerGuard\Console\Commands;

use Carbon\CarbonPeriod;
use Illuminate\Console\Command;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardBan;
use JeffersonGoncalves\ScannerGuard\ScannerGuard;

/**
 * Daily counters are bumped at ban time (ScannerGuard::ban()), keyed by the
 * banned_at day. This command keeps that history complete and bounded:
 *
 *  1. reconciles every day from the oldest remaining ban (or --date) up to
 *     yesterday against the ban rows still present — never lowering a
 *     counter, since deleted rows can't be recounted;
 *  2. purges expired bans once their day has been reconciled;
 *  3. prunes ban rows past retention_days.
 */
class AggregateAndPruneCommand extends Command
{
    protected $signature = 'scanner-guard:aggregate-and-prune
        {--date= : Reconcile from this date (Y-m-d) instead of the oldest remaining ban}
        {--rebuild : Overwrite the reconciled days from the remaining ban rows instead of keeping the higher value}';

    protected $description = 'Reconcile scanner_guard_ban_daily_stats by ban day, purge expired bans and prune old ban rows.';

    public function handle(ScannerGuard $scannerGuard): int
    {
        $yesterday = Carbon::yesterday();
        $start = $this->option('date')
            ? Carbon::parse((string) $this->option('date'))->startOfDay()
            : $this->oldestBanDay($yesterday);

        if ($this->option('rebuild')) {
            DB::table($scannerGuard->dailyStatsTable())
                ->whereBetween('date', [$start->toDateString(), $yesterday->toDateString()])
                ->delete();
        }

        $this->reconcile($scannerGuard, $start, $yesterday);
        $this->purgeExpired();
        $this->prune();

        return self::SUCCESS;
    }

    protected function oldestBanDay(Carbon $fallback): Carbon
    {
        $oldest = ScannerGuardBan::query()->min('banned_at');

        return $oldest ? Carbon::parse($oldest)->startOfDay()->min($fallback) : $fallback;
    }

    protected function reconcile(ScannerGuard $scannerGuard, Carbon $from, Carbon $to): void
    {
        /** @var array<string, array{bans_count: int, hits_total: int, reason_stats: array<string, int>, top_matched_values: array<string, int>}> $days */
        $days = [];

        foreach (CarbonPeriod::create($from, $to) as $day) {
            $days[$day->toDateString()] = ['bans_count' => 0, 'hits_total' => 0, 'reason_stats' => [], 'top_matched_values' => []];
        }

        // ponytail: groups in PHP for portable per-day bucketing (no DATE()
        // dialect differences); the table is bounded by purge/retention.
        $bans = ScannerGuardBan::query()
            ->whereBetween('banned_at', [$from->copy()->startOfDay(), $to->copy()->endOfDay()])
            ->select(['reason', 'matched_value', 'hit_count', 'banned_at'])
            ->cursor();

        foreach ($bans as $ban) {
            $date = $ban->banned_at->toDateString();
            $days[$date]['bans_count']++;
            $days[$date]['hits_total'] += $ban->hit_count;
            $days[$date]['reason_stats'][$ban->reason] = ($days[$date]['reason_stats'][$ban->reason] ?? 0) + 1;
            $days[$date]['top_matched_values'][$ban->matched_value] = ($days[$date]['top_matched_values'][$ban->matched_value] ?? 0) + $ban->hit_count;
        }

        foreach ($days as $date => $stats) {
            $scannerGuard->mergeDailyStats($date, $stats, fn (int $a, int $b): int => max($a, $b));
        }
    }

    /**
     * Only bans from days already reconciled (before today) — today's are
     * counted live and reconciled by tomorrow's run.
     */
    protected function purgeExpired(): void
    {
        $days = config('scanner-guard.purge_expired_after_days', 0);

        if ($days === null || $days === '') {
            return;
        }

        ScannerGuardBan::query()
            ->where('expires_at', '<=', now()->subDays((int) $days))
            ->where('banned_at', '<', Carbon::today())
            ->delete();
    }

    protected function prune(): void
    {
        ScannerGuardBan::query()
            ->where('expires_at', '<', now()->subDays((int) config('scanner-guard.retention_days', 90)))
            ->delete();
    }
}
