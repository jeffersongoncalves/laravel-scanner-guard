<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use JeffersonGoncalves\ScannerGuard\Events\AgentEventRecorded;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardAgentEvent;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardAgentMetric;
use JeffersonGoncalves\ScannerGuard\ScannerGuard;
use JeffersonGoncalves\ScannerGuard\ScannerGuardServiceProvider;

beforeEach(function () {
    config(['scanner-guard.http.server.enabled' => true, 'scanner-guard.http.secret' => 'shared-secret']);
    (new ScannerGuardServiceProvider(app()))->packageBooted();
});

function postSigned(string $uri, array $payload, string $secret = 'shared-secret')
{
    $timestamp = (string) now()->timestamp;
    $body = json_encode($payload, JSON_THROW_ON_ERROR);

    return test()->call('POST', $uri, [], [], [], [
        'CONTENT_TYPE' => 'application/json',
        'HTTP_ACCEPT' => 'application/json',
        'HTTP_X_TIMESTAMP' => $timestamp,
        'HTTP_X_SIGNATURE' => app(ScannerGuard::class)->sign($timestamp, $body, $secret),
    ], $body);
}

function agentEvent(array $overrides = []): array
{
    return array_merge([
        'source' => 'vps-01',
        'rule' => 'ssh_login',
        'ip' => '203.0.113.9',
        'pattern' => 'Accepted (?P<method>\S+) for (?P<user>\S+) from <ip>',
        'fields' => ['user' => 'deploy', 'method' => 'publickey', 'key' => 'SHA256:abc'],
        'line' => 'Accepted publickey for deploy from <ip> port 50000 ssh2',
        'ignored' => false,
        'at' => '2026-11-26T20:00:00Z',
    ], $overrides);
}

it('stores a signed event, marks the first one and fires AgentEventRecorded', function () {
    Event::fake([AgentEventRecorded::class]);

    postSigned('/scanner-guard/bans/events', agentEvent())->assertCreated();
    $this->travel(1)->days();
    postSigned('/scanner-guard/bans/events', agentEvent(['at' => '2026-11-27T20:00:00Z']))->assertCreated();
    postSigned('/scanner-guard/bans/events', agentEvent(['fields' => ['user' => 'root', 'method' => 'publickey']]))->assertCreated();

    $events = ScannerGuardAgentEvent::query()->orderBy('id')->get();
    expect($events)->toHaveCount(3)
        ->and($events->pluck('first_seen')->all())->toBe([true, false, true])
        ->and($events[0]->source)->toBe('vps-01')
        ->and($events[0]->rule)->toBe('ssh_login')
        ->and($events[0]->ip_hash)->toBe(app(ScannerGuard::class)->hashIp('203.0.113.9'))
        ->and($events[0]->fields)->toEqual(['user' => 'deploy', 'method' => 'publickey', 'key' => 'SHA256:abc']) // MySQL JSON reorders keys
        ->and($events[0]->occurred_at->toIso8601String())->toBe('2026-11-26T20:00:00+00:00');

    Event::assertDispatchedTimes(AgentEventRecorded::class, 3);
});

it('keeps the raw IP and the line only with store_details, encrypted', function () {
    postSigned('/scanner-guard/bans/events', agentEvent())->assertCreated();
    expect(ScannerGuardAgentEvent::query()->sole())
        ->ip->toBeNull()
        ->line->toBeNull();

    config(['scanner-guard.store_details' => true]);
    postSigned('/scanner-guard/bans/events', agentEvent(['ip' => '198.51.100.4']))->assertCreated();

    $event = ScannerGuardAgentEvent::query()->latest('id')->first();
    expect($event->ip)->toBe('198.51.100.4')
        ->and($event->line)->toContain('from <ip> port')
        ->and($event->getRawOriginal('ip'))->not->toContain('198.51.100.4');
});

it('rejects bad signatures, replays and invalid payloads', function () {
    postSigned('/scanner-guard/bans/events', agentEvent(), 'wrong')->assertForbidden();
    postSigned('/scanner-guard/bans/events', agentEvent(['ip' => 'not-an-ip']))->assertUnprocessable();
    postSigned('/scanner-guard/bans/events', agentEvent(['rule' => str_repeat('x', 31)]))->assertUnprocessable();
    postSigned('/scanner-guard/bans/events', agentEvent(['fields' => ['user' => str_repeat('x', 256)]]))->assertUnprocessable();

    expect(ScannerGuardAgentEvent::query()->count())->toBe(0);
});

it('drops field names that are not identifiers', function () {
    postSigned('/scanner-guard/bans/events', agentEvent(['fields' => ['user' => 'deploy', 'bad name' => 'x', '0' => 'y']]))->assertCreated();

    expect(ScannerGuardAgentEvent::query()->sole()->fields)->toBe(['user' => 'deploy']);
});

it('answers 404 without the events table, so the agent stops sending', function () {
    Schema::drop('scanner_guard_agent_events');
    app()->forgetInstance(ScannerGuard::class);

    try {
        postSigned('/scanner-guard/bans/events', agentEvent())->assertNotFound();
    } finally {
        // MySQL and PostgreSQL roll the migrations back between tests: the down() needs the table.
        (require __DIR__.'/../../database/migrations/create_scanner_guard_agent_events_table.php.stub')->up();
    }
});

it('sums the heartbeat matches per source, rule and hour', function () {
    $this->travelTo('2026-11-26 10:15:00');
    $beat = ['source' => 'vps-01', 'version' => '2.6.0', 'rules' => ['ssh_bruteforce', 'web_attack'], 'active_bans' => 1];

    postSigned('/scanner-guard/bans/heartbeat', $beat + ['matches' => ['ssh_bruteforce' => 4, 'web_attack' => 0]])->assertNoContent();
    $this->travel(1)->minutes();
    postSigned('/scanner-guard/bans/heartbeat', $beat + ['matches' => ['ssh_bruteforce' => 3]])->assertNoContent();
    $this->travelTo('2026-11-26 11:01:00');
    postSigned('/scanner-guard/bans/heartbeat', $beat + ['matches' => ['ssh_bruteforce' => 2, 'web_attack' => 5]])->assertNoContent();
    postSigned('/scanner-guard/bans/heartbeat', ['source' => 'old-agent'] + $beat)->assertNoContent(); // no matches: nothing

    $rows = ScannerGuardAgentMetric::query()->orderBy('hour')->orderBy('rule')->get()
        ->map(fn ($m) => [$m->source, $m->rule, $m->hour->format('H:i'), $m->matches])->all();

    expect($rows)->toBe([
        ['vps-01', 'ssh_bruteforce', '10:00', 7],
        ['vps-01', 'ssh_bruteforce', '11:00', 2],
        ['vps-01', 'web_attack', '11:00', 5],
    ]);
});

it('validates the heartbeat matches', function () {
    $beat = ['source' => 'vps-01', 'version' => '2.6.0'];

    postSigned('/scanner-guard/bans/heartbeat', $beat + ['matches' => ['ssh_bruteforce' => -1]])->assertUnprocessable();
    postSigned('/scanner-guard/bans/heartbeat', $beat + ['matches' => [str_repeat('x', 31) => 3]])->assertNoContent(); // skipped

    expect(ScannerGuardAgentMetric::query()->count())->toBe(0);
});

it('prunes agent events and metrics past retention_days', function () {
    config(['scanner-guard.retention_days' => 30]);
    $sg = app(ScannerGuard::class);

    $sg->recordAgentEvent('vps-01', 'ssh_login', '203.0.113.9', null, [], null, false, now()->subDays(31));
    $sg->recordAgentEvent('vps-01', 'ssh_login', '203.0.113.9', null, [], null, false, now()->subDays(29));
    ScannerGuardAgentMetric::query()->create(['source' => 'vps-01', 'rule' => 'ssh', 'hour' => now()->subDays(31)->startOfHour(), 'matches' => 1]);
    ScannerGuardAgentMetric::query()->create(['source' => 'vps-01', 'rule' => 'ssh', 'hour' => now()->subDays(29)->startOfHour(), 'matches' => 1]);

    $this->artisan('scanner-guard:aggregate-and-prune')->assertSuccessful();

    expect(ScannerGuardAgentEvent::query()->count())->toBe(1)
        ->and(ScannerGuardAgentMetric::query()->count())->toBe(1);
});
