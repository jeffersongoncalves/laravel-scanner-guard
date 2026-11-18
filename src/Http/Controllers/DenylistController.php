<?php

declare(strict_types=1);

namespace JeffersonGoncalves\ScannerGuard\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use JeffersonGoncalves\ScannerGuard\ScannerGuard;

/**
 * Serves the central denylist to satellites running scanner-guard:pull-denylist.
 * Only registered when scanner-guard.http.server.enabled is true. Signed like
 * the POST, over "X-Timestamp.X-Source"; read-only, so no nonce.
 */
class DenylistController
{
    public function __invoke(Request $request, ScannerGuard $scannerGuard): JsonResponse
    {
        $source = (string) $request->header('X-Source');
        $timestamp = (string) $request->header('X-Timestamp');
        $secret = $scannerGuard->secretFor($source);

        abort_unless(
            filled($secret)
                && ctype_digit($timestamp)
                && abs(now()->timestamp - (int) $timestamp) <= (int) config('scanner-guard.http.tolerance', 300)
                && hash_equals($scannerGuard->sign($timestamp, $source, $secret), (string) $request->header('X-Signature')),
            403
        );

        return response()->json($scannerGuard->denylist());
    }
}
