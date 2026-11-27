<?php

declare(strict_types=1);

namespace JeffersonGoncalves\ScannerGuard\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardAgentDiagnosis;
use JeffersonGoncalves\ScannerGuard\ScannerGuard;
use Symfony\Component\HttpFoundation\Response;

/**
 * Receives the report of a diagnosis the central app asked of an agent
 * (ScannerGuard::requestDiagnosis()), signed like a forwarded ban. Only
 * registered when scanner-guard.http.server.enabled is true; 404 until the
 * create_scanner_guard_agent_diagnostics_table migration runs, or when the
 * source has no open diagnosis with that id.
 */
class RecordAgentDiagnosisController
{
    public function __invoke(Request $request, ScannerGuard $scannerGuard): Response
    {
        abort_unless($scannerGuard->hasTable(ScannerGuardAgentDiagnosis::class), 404);

        $signature = $scannerGuard->verifyAgentRequest($request);
        $tolerance = (int) config('scanner-guard.http.tolerance', 300);

        // The signed JSON body only, never the unsigned query string.
        $data = Validator::make($request->json()->all(), [
            'source' => ['required', 'string', 'max:100'],
            'id' => ['required', 'integer', 'min:1'],
            'report' => ['required', 'string', 'max:70000'],
        ])->validate();

        abort_unless($scannerGuard->cache()->add("scanner-guard:nonce:{$signature}", true, $tolerance * 2), 409);

        abort_unless($scannerGuard->recordDiagnosis($data['source'], (int) $data['id'], $data['report']), 404);

        return response()->noContent(201);
    }
}
