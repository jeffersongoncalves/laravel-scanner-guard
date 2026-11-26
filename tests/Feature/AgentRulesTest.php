<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Schema;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardAgentRule;
use JeffersonGoncalves\ScannerGuard\ScannerGuard;
use JeffersonGoncalves\ScannerGuard\ScannerGuardServiceProvider;

beforeEach(function () {
    config(['scanner-guard.http.server.enabled' => true, 'scanner-guard.http.secret' => 'shared-secret']);
    (new ScannerGuardServiceProvider(app()))->packageBooted();
});

function pullAsAgent()
{
    $timestamp = (string) now()->timestamp;

    return test()->getJson('/scanner-guard/bans', [
        'X-Source' => 'vps-01',
        'X-Timestamp' => $timestamp,
        'X-Signature' => app(ScannerGuard::class)->sign($timestamp, 'vps-01', 'shared-secret'),
    ])->assertOk();
}

it('serves the agent rules in seconds, keyed by name', function () {
    ScannerGuardAgentRule::query()->create(['name' => 'web_attack', 'threshold' => 5, 'window' => '10m', 'ban' => '1d, 7d,30d']);
    ScannerGuardAgentRule::query()->create(['name' => 'ssh_bruteforce', 'threshold' => 3, 'window' => '1h', 'ban' => '90s']);

    expect(pullAsAgent()->json('agent_rules'))->toBe([
        'ssh_bruteforce' => ['threshold' => 3, 'window' => 3600, 'ban' => [90]],
        'web_attack' => ['threshold' => 5, 'window' => 600, 'ban' => [86400, 604800, 2592000]],
    ]);
});

it('sends an empty object without rows, so agents go back to their own', function () {
    expect(pullAsAgent()->getContent())->toContain('"agent_rules":{}');
});

it('leaves out a row out of range', function (array $row) {
    ScannerGuardAgentRule::query()->create($row + ['name' => 'web_attack', 'threshold' => 5, 'window' => '10m', 'ban' => '1d']);
    ScannerGuardAgentRule::query()->create(['name' => 'ssh_bruteforce', 'threshold' => 5, 'window' => '1h', 'ban' => '1d']);

    expect(array_keys(pullAsAgent()->json('agent_rules')))->toBe(['ssh_bruteforce']);
})->with([
    'no threshold' => [['threshold' => 0]],
    'threshold too high' => [['threshold' => ScannerGuardAgentRule::MAX_THRESHOLD + 1]],
    'bad window' => [['window' => '10 minutes']],
    'window too long' => [['window' => '31d']],
    'zero ban' => [['ban' => '0s']],
    'ban too long' => [['ban' => '1d, 366d']],
    'empty step' => [['ban' => '1d,,7d']],
    'too many steps' => [['ban' => implode(',', array_fill(0, 11, '1d'))]],
]);

it('leaves the key out until the migration ran', function () {
    Schema::drop('scanner_guard_agent_rules');

    try {
        expect(pullAsAgent()->json())->not->toHaveKey('agent_rules');
    } finally {
        // MySQL and PostgreSQL roll the migrations back between tests: the down() needs the table.
        Schema::create('scanner_guard_agent_rules', function ($table) {
            $table->id();
            $table->string('name', 30)->unique();
            $table->unsignedInteger('threshold');
            $table->string('window', 20);
            $table->string('ban');
            $table->timestamps();
        });
    }
});

it('parses durations like the agent', function (string $value, ?int $seconds) {
    expect(ScannerGuardAgentRule::parseDuration($value))->toBe($seconds);
})->with([
    ['45s', 45], ['10m', 600], [' 2h ', 7200], ['7d', 604800],
    ['0d', null], ['1w', null], ['1.5h', null], ['-1d', null], ['', null], ['1h30m', null],
]);
