<?php

declare(strict_types=1);

use Illuminate\Console\Scheduling\Schedule;
use JeffersonGoncalves\ScannerGuard\ScannerGuardServiceProvider;
use JeffersonGoncalves\ScannerGuard\Tests\Fixtures\RecordingSink;

it('self-schedules aggregate-and-prune daily by default', function () {
    $events = app(Schedule::class)->events();

    $event = collect($events)->first(
        fn ($event) => str_contains($event->command ?? '', 'scanner-guard:aggregate-and-prune')
    );

    expect($event)->not->toBeNull();
});

it('schedules sync-denylist every minute only when sinks are configured', function () {
    $syncEvent = fn () => collect(app(Schedule::class)->events())->first(
        fn ($event) => str_contains($event->command ?? '', 'scanner-guard:sync-denylist')
    );

    expect($syncEvent())->toBeNull();

    // The app is already booted, so the provider's booted() callback runs at once.
    config(['scanner-guard.sinks' => [RecordingSink::class]]);
    (new ScannerGuardServiceProvider($this->app))->packageBooted();

    expect($syncEvent()?->expression)->toBe('* * * * *');
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
