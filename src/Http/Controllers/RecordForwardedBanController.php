<?php

declare(strict_types=1);

namespace JeffersonGoncalves\ScannerGuard\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Validator;
use JeffersonGoncalves\ScannerGuard\ScannerGuard;
use Symfony\Component\HttpFoundation\Response;

/**
 * Receives bans forwarded by satellite apps running the "http" driver.
 * Only registered when scanner-guard.http.server.enabled is true.
 */
class RecordForwardedBanController
{
    public function __invoke(Request $request, ScannerGuard $scannerGuard): Response
    {
        $timestamp = (string) $request->header('X-Timestamp');
        $signature = (string) $request->header('X-Signature');
        $tolerance = (int) config('scanner-guard.http.tolerance', 300);
        // The claimed source only picks the secret; the signature then proves it.
        $secret = $scannerGuard->secretFor($request->json('source'));

        abort_unless(
            filled($secret)
                && ctype_digit($timestamp)
                && abs(now()->timestamp - (int) $timestamp) <= $tolerance
                && hash_equals($scannerGuard->sign($timestamp, $request->getContent(), $secret), $signature),
            403
        );

        // The signed JSON body only: $request->validate() would also read the
        // unsigned query string, letting it fill in a missing field (e.g. source).
        $data = Validator::make($request->json()->all(), [
            'ip' => ['required', 'ip'],
            'reason' => ['required', 'string', 'max:30'],
            'matched_value' => ['required', 'string', 'max:255'],
            'hit_count' => ['required', 'integer', 'min:1'],
            'banned_at' => ['required', 'date'],
            'expires_at' => ['required', 'date', 'after:banned_at'],
            'offense' => ['nullable', 'integer', 'min:1', 'max:65535'],
            'source' => ['nullable', 'string', 'max:100'],
            'path' => ['nullable', 'string'],
        ])->validate();

        // A signature is only ever accepted once inside its tolerance window
        // (consumed after validation, so a rejected payload can be resent).
        abort_unless($scannerGuard->cache()->add("scanner-guard:nonce:{$signature}", true, $tolerance * 2), 409);

        $scannerGuard->recordForwardedBan(
            $data['ip'],
            $data['reason'],
            $data['matched_value'],
            (int) $data['hit_count'],
            // Satellites may run another timezone; store in ours.
            Carbon::parse($data['banned_at'])->setTimezone(config('app.timezone')),
            Carbon::parse($data['expires_at'])->setTimezone(config('app.timezone')),
            isset($data['offense']) ? (int) $data['offense'] : null,
            $data['source'] ?? null,
            $data['path'] ?? null,
        );

        return response()->noContent(201);
    }
}
