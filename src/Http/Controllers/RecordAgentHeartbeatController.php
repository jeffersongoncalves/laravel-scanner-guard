<?php

declare(strict_types=1);

namespace JeffersonGoncalves\ScannerGuard\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Validator;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardAgent;
use JeffersonGoncalves\ScannerGuard\ScannerGuard;
use Symfony\Component\HttpFoundation\Response;

/**
 * Receives heartbeats from scanner-guard-agent, signed exactly like a
 * forwarded ban. Only registered when scanner-guard.http.server.enabled is true.
 */
class RecordAgentHeartbeatController
{
    public function __invoke(Request $request, ScannerGuard $scannerGuard): Response
    {
        $timestamp = (string) $request->header('X-Timestamp');
        $signature = (string) $request->header('X-Signature');
        $tolerance = (int) config('scanner-guard.http.tolerance', 300);
        $secret = $scannerGuard->secretFor($request->json('source'));

        abort_unless(
            filled($secret)
                && ctype_digit($timestamp)
                && abs(now()->timestamp - (int) $timestamp) <= $tolerance
                && hash_equals($scannerGuard->sign($timestamp, $request->getContent(), $secret), $signature),
            403
        );

        // The signed JSON body only, never the unsigned query string.
        $data = Validator::make($request->json()->all(), [
            'source' => ['required', 'string', 'max:100'],
            'version' => ['nullable', 'string', 'max:50'],
            'rules' => ['nullable', 'array', 'max:100'],
            'rules.*' => ['string', 'max:30'],
            'active_bans' => ['nullable', 'integer', 'min:0'],
            'started_at' => ['nullable', 'date'],
        ])->validate();

        abort_unless($scannerGuard->cache()->add("scanner-guard:nonce:{$signature}", true, $tolerance * 2), 409);

        ScannerGuardAgent::query()->updateOrCreate(['source' => $data['source']], [
            'version' => $data['version'] ?? null,
            'rules' => array_values($data['rules'] ?? []),
            'active_bans' => (int) ($data['active_bans'] ?? 0),
            'started_at' => isset($data['started_at'])
                ? Carbon::parse($data['started_at'])->setTimezone(config('app.timezone'))
                : null,
            'last_seen_at' => now(),
        ]);

        return response()->noContent();
    }
}
