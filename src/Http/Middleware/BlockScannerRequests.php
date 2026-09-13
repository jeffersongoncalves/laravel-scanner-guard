<?php

declare(strict_types=1);

namespace JeffersonGoncalves\ScannerGuard\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardBan;
use JeffersonGoncalves\ScannerGuard\ScannerGuard;
use JeffersonGoncalves\VisitorFingerprint\Contracts\GeoIpDriver;
use Symfony\Component\HttpFoundation\Response;

/**
 * Not auto-registered globally — attach it yourself to whichever route
 * group should get scanner protection, e.g. in bootstrap/app.php:
 *
 *   ->withMiddleware(fn ($middleware) => $middleware->appendToGroup('web', BlockScannerRequests::class))
 *
 * or via the `scanner-guard` route alias this package registers.
 */
class BlockScannerRequests
{
    public function __construct(protected ScannerGuard $scannerGuard) {}

    public function handle(Request $request, Closure $next): Response
    {
        if (! config('scanner-guard.enabled', true)) {
            return $next($request);
        }

        $ip = $request->ip();

        if (! $ip) {
            return $next($request);
        }

        $status = (int) config('scanner-guard.response_status', 404);

        // Cheapest possible check first: already banned, no further work.
        if ($this->scannerGuard->isBanned($ip)) {
            return response('', $status);
        }

        $blocklist = (array) config('scanner-guard.asn_blocklist', []);

        if ($blocklist !== []) {
            $asn = app(GeoIpDriver::class)->resolve($ip)->asn;

            if ($this->scannerGuard->isAsnBlocked($asn)) {
                $this->scannerGuard->ban($ip, ScannerGuardBan::REASON_ASN, (string) $asn, 1, $request->path());

                return response('', $status);
            }
        }

        $matched = $this->scannerGuard->matchScannerPath($request->path());

        if ($matched === null) {
            return $next($request);
        }

        $hits = $this->scannerGuard->registerHit($ip);

        if ($hits >= (int) config('scanner-guard.ban_threshold', 3)) {
            $this->scannerGuard->ban($ip, ScannerGuardBan::REASON_SCANNER_PATH, $matched, $hits, $request->path());

            return response('', $status);
        }

        return $next($request);
    }
}
