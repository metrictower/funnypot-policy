<?php

namespace Funnypot\Policy\Clock;

use Funnypot\Policy\Port\Clock;

/**
 * The obvious Clock: wall time from time().
 *
 * Exists so a host that has no reason to care about time injection does not have to write one.
 * A host with a testable clock of its own should bind that instead — this is a default, not a
 * recommendation.
 *
 * Companion to Geo\NullGeoIp and Log\NullLogger: every port policy defines should have a usable
 * stock implementation, so the only thing a host is REQUIRED to supply is the StateStore.
 */
final class SystemClock implements Clock
{
    public function now()
    {
        return time();
    }
}
