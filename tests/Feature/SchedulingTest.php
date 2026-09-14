<?php

declare(strict_types=1);

use Illuminate\Console\Scheduling\Schedule;

it('self-schedules aggregate-and-prune daily by default', function () {
    $events = app(Schedule::class)->events();

    $event = collect($events)->first(
        fn ($event) => str_contains($event->command ?? '', 'scanner-guard:aggregate-and-prune')
    );

    expect($event)->not->toBeNull();
});

it('does not schedule aggregate-and-prune when disabled via env', function () {
    putenv('SCANNER_GUARD_AUTO_PRUNE=false');
    $_ENV['SCANNER_GUARD_AUTO_PRUNE'] = 'false';

    $this->refreshApplication();

    $events = app(Schedule::class)->events();

    $event = collect($events)->first(
        fn ($event) => str_contains($event->command ?? '', 'scanner-guard:aggregate-and-prune')
    );

    expect($event)->toBeNull();

    putenv('SCANNER_GUARD_AUTO_PRUNE');
    unset($_ENV['SCANNER_GUARD_AUTO_PRUNE']);
});
