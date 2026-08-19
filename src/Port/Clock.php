<?php

namespace Funnypot\Policy\Port;

/**
 * Injected time source (design §2.4) so TTL/decay/window math is deterministic in tests — the state
 * machine's "7 days AND 5,000 requests", the suppression windows, the TTL-decay scoring all read this
 * clock, never time().
 */
interface Clock
{
    /** @return int epoch seconds */
    public function now();
}
