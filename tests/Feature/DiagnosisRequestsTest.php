<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardAgentDiagnosis;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardDiagnosisRequest;
use JeffersonGoncalves\ScannerGuard\ScannerGuard;

function requestsMigration(): object
{
    return require __DIR__.'/../../database/migrations/create_scanner_guard_diagnosis_requests_table.php.stub';
}

it('groups the diagnoses of one IP under one request, with who asked', function () {
    $sent = app(ScannerGuard::class)->requestDiagnosis('2001:DB8::1', ['vps-01', 'vps-02', 'vps-01'], 30, 'Ana');

    $request = ScannerGuardDiagnosisRequest::query()->sole();

    expect($request->ip)->toBe('2001:db8::1')
        ->and($request->capture)->toBe(30)
        ->and($request->requested_by)->toBe('Ana')
        ->and($request->diagnoses()->pluck('source')->sort()->values()->all())->toBe(['vps-01', 'vps-02'])
        ->and($sent->pluck('request_id')->unique()->all())->toBe([$request->id])
        // The agents still get their own row's id.
        ->and(app(ScannerGuard::class)->denylist('vps-01')['diagnostics'])->toBe([['id' => $sent->first()->id, 'ip' => '2001:db8::1', 'capture' => 30]]);
});

it('still asks the agents before the diagnosis_requests migration ran', function () {
    requestsMigration()->down();

    try {
        expect(app(ScannerGuard::class)->requestDiagnosis('203.0.113.9', ['vps-01'])->sole()->source)->toBe('vps-01');
    } finally {
        // MySQL and PostgreSQL roll the package migrations back between tests: its down() needs the table back.
        if (! Schema::hasTable('scanner_guard_diagnosis_requests')) {
            DB::table('scanner_guard_agent_diagnostics')->delete();
            requestsMigration()->up();
        }
    }
});

it('groups the diagnoses asked before the migration, one request per IP and second', function () {
    $at = now()->subHour()->startOfSecond();
    $make = fn (string $source, string $ip, $createdAt) => ScannerGuardAgentDiagnosis::query()->forceCreate(['source' => $source, 'ip' => $ip, 'capture' => 0, 'created_at' => $createdAt, 'updated_at' => $createdAt]);

    $a1 = $make('vps-01', '203.0.113.9', $at);
    $a2 = $make('vps-02', '203.0.113.9', $at);
    $other = $make('vps-01', '203.0.113.10', $at);
    $later = $make('vps-01', '203.0.113.9', $at->copy()->addMinute());
    $lost = $make('vps-03', '203.0.113.9', $at);
    DB::table('scanner_guard_agent_diagnostics')->where('id', $lost->id)->update(['ip' => 'not encrypted with this key']);

    $migration = requestsMigration();
    (new ReflectionMethod($migration, 'groupExistingDiagnoses'))->invoke($migration);

    $requestOf = fn (ScannerGuardAgentDiagnosis $d): ?int => $d->fresh()->request_id;

    expect(ScannerGuardDiagnosisRequest::query()->count())->toBe(3)
        ->and($requestOf($a1))->not->toBeNull()->toBe($requestOf($a2))
        ->and($requestOf($other))->not->toBe($requestOf($a1))
        ->and($requestOf($later))->not->toBe($requestOf($a1))
        ->and($requestOf($lost))->toBeNull()
        ->and(ScannerGuardDiagnosisRequest::query()->find($requestOf($a1))->ip)->toBe('203.0.113.9');
});

it('prunes requests past retention_days with their diagnoses', function () {
    app(ScannerGuard::class)->requestDiagnosis('203.0.113.9', ['vps-01', 'vps-02']);
    ScannerGuardDiagnosisRequest::query()->update(['created_at' => now()->subDays(100)]);
    ScannerGuardAgentDiagnosis::query()->update(['created_at' => now()->subDays(100)]);
    app(ScannerGuard::class)->requestDiagnosis('203.0.113.10', ['vps-01']);

    Artisan::call('scanner-guard:aggregate-and-prune');

    expect(ScannerGuardDiagnosisRequest::query()->sole()->ip)->toBe('203.0.113.10')
        ->and(ScannerGuardAgentDiagnosis::query()->count())->toBe(1);
});
