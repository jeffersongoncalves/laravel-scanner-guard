<?php

declare(strict_types=1);

namespace JeffersonGoncalves\ScannerGuard\Contracts;

/**
 * Pushes the denylist to something that blocks before PHP (a web server, a
 * CDN/WAF, a reverse proxy). Listed in scanner-guard.sinks and called by
 * scanner-guard:sync-denylist with the full current list every time, so a
 * sink only has to replace its previous state, never diff bans one by one.
 * Throwing marks this sink as failed for the run; the other sinks still run.
 */
interface DenylistSink
{
    /**
     * @param  list<array{ip: string, reason: string, expires_at: string|null}>  $entries  one per IP/CIDR, static ip_blocklist entries first (reason "static", no expiry), IPs validated, reasons limited to [A-Za-z0-9_.-]
     */
    public function sync(array $entries): void;
}
