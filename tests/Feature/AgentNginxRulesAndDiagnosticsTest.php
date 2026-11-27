<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardAgentDiagnosis;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardAgentNginxRule;
use JeffersonGoncalves\ScannerGuard\ScannerGuard;
use JeffersonGoncalves\ScannerGuard\ScannerGuardServiceProvider;

beforeEach(function () {
    config(['scanner-guard.http.server.enabled' => true, 'scanner-guard.http.secret' => 'shared-secret']);
    (new ScannerGuardServiceProvider(app()))->packageBooted();
});

function pullAs(string $source)
{
    $timestamp = (string) now()->timestamp;

    return test()->getJson('/scanner-guard/bans', [
        'X-Source' => $source,
        'X-Timestamp' => $timestamp,
        'X-Signature' => app(ScannerGuard::class)->sign($timestamp, $source, 'shared-secret'),
    ])->assertOk();
}

function postReport(array $payload)
{
    $timestamp = (string) now()->timestamp;
    $body = json_encode($payload, JSON_THROW_ON_ERROR);

    return test()->call('POST', '/scanner-guard/bans/diagnostics', [], [], [], [
        'CONTENT_TYPE' => 'application/json',
        'HTTP_ACCEPT' => 'application/json',
        'HTTP_X_TIMESTAMP' => $timestamp,
        'HTTP_X_SIGNATURE' => app(ScannerGuard::class)->sign($timestamp, $body, 'shared-secret'),
    ], $body);
}

it('sends each agent the optional nginx rules turned on for it', function () {
    ScannerGuardAgentNginxRule::query()->create(['name' => 'cms', 'enabled' => true, 'except' => ['adwp']]);
    ScannerGuardAgentNginxRule::query()->create(['name' => 'rfi', 'enabled' => false]);
    ScannerGuardAgentNginxRule::query()->create(['name' => 'empty-agent', 'enabled' => true]);
    ScannerGuardAgentNginxRule::query()->create(['name' => 'unknown', 'enabled' => true]); // written around the panel

    expect(pullAs('vps-01')->json('nginx_rules'))->toBe(['cms', 'empty-agent'])
        ->and(pullAs('adwp')->json('nginx_rules'))->toBe(['empty-agent']);
});

it('sends an empty list without rows, so agents turn every optional rule off', function () {
    expect(pullAs('vps-01')->getContent())->toContain('"nginx_rules":[]');
});

it('leaves the agent keys out of a pull without a source', function () {
    expect(app(ScannerGuard::class)->denylist())->not->toHaveKeys(['nginx_rules', 'diagnostics']);
});

it('hands a diagnosis to its agent once, again if unanswered, and stores the report', function () {
    $requests = app(ScannerGuard::class)->requestDiagnosis('2001:DB8::1', ['vps-01', 'vps-02', 'vps-01'], 60);

    expect($requests)->toHaveCount(2);

    $vps01 = $requests->firstWhere('source', 'vps-01');

    expect(pullAs('vps-01')->json('diagnostics'))->toBe([['id' => $vps01->id, 'ip' => '2001:db8::1', 'capture' => 60]])
        ->and(pullAs('vps-01')->json('diagnostics'))->toBe([])
        ->and($vps01->fresh()->status())->toBe('running');

    $this->travel(ScannerGuardAgentDiagnosis::RESEND_AFTER + 1)->seconds();
    expect(pullAs('vps-01')->json('diagnostics.0.id'))->toBe($vps01->id);

    postReport(['source' => 'vps-01', 'id' => $vps01->id, 'report' => "== verdict ==\n  Nothing on this server blocks 2001:db8::1."])->assertCreated();

    expect($vps01->fresh())
        ->status()->toBe('done')
        ->report->toContain('Nothing on this server blocks')
        ->and(pullAs('vps-01')->json('diagnostics'))->toBe([])
        // Encrypted at rest: a client's IP.
        ->and(DB::table('scanner_guard_agent_diagnostics')->where('id', $vps01->id)->value('ip'))->not->toContain('2001:db8::1');
});

it('refuses a report for another source, a closed diagnosis or an unsigned one', function () {
    $diagnosis = app(ScannerGuard::class)->requestDiagnosis('203.0.113.9', ['vps-01'])->first();

    postReport(['source' => 'vps-02', 'id' => $diagnosis->id, 'report' => 'x'])->assertNotFound();
    postReport(['source' => 'vps-01', 'id' => $diagnosis->id, 'report' => 'x'])->assertCreated();
    postReport(['source' => 'vps-01', 'id' => $diagnosis->id, 'report' => 'again'])->assertNotFound();

    $this->postJson('/scanner-guard/bans/diagnostics', ['source' => 'vps-01', 'id' => $diagnosis->id, 'report' => 'x'])->assertForbidden();

    expect($diagnosis->fresh()->report)->toBe('x');
});

it('stops handing out a diagnosis nobody answered after an hour', function () {
    app(ScannerGuard::class)->requestDiagnosis('203.0.113.9', ['vps-01']);

    $this->travel(ScannerGuardAgentDiagnosis::EXPIRE_AFTER + 1)->seconds();

    expect(pullAs('vps-01')->json('diagnostics'))->toBe([])
        ->and(ScannerGuardAgentDiagnosis::query()->first()->status())->toBe('expired');
});

it('validates the IP and the capture', function (string $ip, int $capture) {
    app(ScannerGuard::class)->requestDiagnosis($ip, ['vps-01'], $capture);
})->with([
    'not an IP' => ['example.com', 0],
    'negative capture' => ['203.0.113.9', -1],
    'capture too long' => ['203.0.113.9', ScannerGuardAgentDiagnosis::MAX_CAPTURE + 1],
])->throws(InvalidArgumentException::class);

it('prunes diagnoses past retention_days', function () {
    config(['scanner-guard.retention_days' => 30]);
    app(ScannerGuard::class)->requestDiagnosis('203.0.113.9', ['vps-01']);

    $this->travel(31)->days();
    Artisan::call('scanner-guard:aggregate-and-prune');

    expect(ScannerGuardAgentDiagnosis::query()->count())->toBe(0);
});
