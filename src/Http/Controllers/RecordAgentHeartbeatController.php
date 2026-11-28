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
        $signature = $scannerGuard->verifyAgentRequest($request);
        $tolerance = (int) config('scanner-guard.http.tolerance', 300);

        // The signed JSON body only, never the unsigned query string.
        $data = Validator::make($request->json()->all(), [
            'source' => ['required', 'string', 'max:100'],
            'version' => ['nullable', 'string', 'max:50'],
            'rules' => ['nullable', 'array', 'max:100'],
            'rules.*' => ['string', 'max:30'],
            'active_bans' => ['nullable', 'integer', 'min:0'],
            'started_at' => ['nullable', 'date'],
            // Matching lines per rule since the last heartbeat (agent 2.6.0+).
            'matches' => ['nullable', 'array', 'max:100'],
            'matches.*' => ['integer', 'min:0'],
            // The server's OS and interface addresses (agent 2.9.0+).
            'os' => ['nullable', 'string', 'max:100'],
            'addresses' => ['nullable', 'array', 'max:32'],
            'addresses.*' => ['ip'],
        ])->validate();

        abort_unless($scannerGuard->cache()->add("scanner-guard:nonce:{$signature}", true, $tolerance * 2), 409);

        $matches = [];
        foreach ((array) ($data['matches'] ?? []) as $rule => $n) {
            if (is_string($rule) && $rule !== '' && mb_strlen($rule) <= 30) {
                $matches[$rule] = (int) $n;
            }
        }
        $scannerGuard->recordAgentMatches($data['source'], $matches);

        // Older agents don't send the host keys: leave those columns alone, so
        // they also keep working before the add_host migration runs.
        $host = array_intersect_key($data, array_flip(['os', 'addresses']));
        if (isset($host['addresses'])) {
            $host['addresses'] = array_values($host['addresses']);
        }

        ScannerGuardAgent::query()->updateOrCreate(['source' => $data['source']], $host + [
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
