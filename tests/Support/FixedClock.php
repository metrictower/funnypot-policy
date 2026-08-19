<?php

namespace Funnypot\Policy\Tests\Support;

use Funnypot\Policy\Port\Clock;

/** Advanceable clock for deterministic TTL/decay/dwell tests. */
final class FixedClock implements Clock
{
    /** @var int */
    private $t;

    public function __construct($start = 1000000000)
    {
        $this->t = (int) $start;
    }

    public function now()
    {
        return $this->t;
    }

    public function advance($secs)
    {
        $this->t += (int) $secs;

        return $this;
    }

    public function set($t)
    {
        $this->t = (int) $t;

        return $this;
    }
}
