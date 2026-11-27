<?php

declare(strict_types=1);

namespace JeffersonGoncalves\ScannerGuard\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Validator;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardAgentEvent;
use JeffersonGoncalves\ScannerGuard\ScannerGuard;
use Symfony\Component\HttpFoundation\Response;

/**
 * Receives the events of scanner-guard-agent report rules (an accepted SSH
 * login, say), signed exactly like a forwarded ban. Only registered when
 * scanner-guard.http.server.enabled is true; 404 (the agent stops sending)
 * until the create_scanner_guard_agent_events_table migration runs.
 */
class RecordAgentEventController
{
    public function __invoke(Request $request, ScannerGuard $scannerGuard): Response
    {
        abort_unless($scannerGuard->hasTable(ScannerGuardAgentEvent::class), 404);

        $signature = $scannerGuard->verifyAgentRequest($request);
        $tolerance = (int) config('scanner-guard.http.tolerance', 300);

        // The signed JSON body only, never the unsigned query string.
        $data = Validator::make($request->json()->all(), [
            'source' => ['required', 'string', 'max:100'],
            'rule' => ['required', 'string', 'max:30'],
            'ip' => ['required', 'ip'],
            'pattern' => ['nullable', 'string', 'max:255'],
            'fields' => ['nullable', 'array', 'max:20'],
            'fields.*' => ['string', 'max:255'],
            'line' => ['nullable', 'string', 'max:1024'],
            'ignored' => ['nullable', 'boolean'],
            'at' => ['required', 'date'],
        ])->validate();

        abort_unless($scannerGuard->cache()->add("scanner-guard:nonce:{$signature}", true, $tolerance * 2), 409);

        $fields = [];
        foreach ((array) ($data['fields'] ?? []) as $name => $value) {
            if (is_string($name) && preg_match('/^[A-Za-z_][A-Za-z0-9_]{0,31}$/', $name)) {
                $fields[$name] = (string) $value;
            }
        }

        $scannerGuard->recordAgentEvent(
            $data['source'],
            $data['rule'],
            $data['ip'],
            $data['pattern'] ?? null,
            $fields,
            $data['line'] ?? null,
            (bool) ($data['ignored'] ?? false),
            // Agents may run another timezone; store in ours.
            Carbon::parse($data['at'])->setTimezone(config('app.timezone')),
        );

        return response()->noContent(201);
    }
}
