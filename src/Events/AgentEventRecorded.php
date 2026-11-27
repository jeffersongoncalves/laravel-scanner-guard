<?php

declare(strict_types=1);

namespace JeffersonGoncalves\ScannerGuard\Events;

use Illuminate\Foundation\Events\Dispatchable;
use JeffersonGoncalves\ScannerGuard\Models\ScannerGuardAgentEvent;

/**
 * Fired for every agent event stored. Listen to it to alert (Discord, mail),
 * e.g. only when $event->first_seen: an SSH login from an IP or with a key this
 * app never saw.
 */
class AgentEventRecorded
{
    use Dispatchable;

    public function __construct(public readonly ScannerGuardAgentEvent $event) {}
}
