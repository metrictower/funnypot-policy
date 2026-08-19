<?php

namespace Funnypot\Policy\Port;

use Funnypot\Policy\ReputationVerdict;

/**
 * The actor-evidence axis (design §2.2). Wraps piece F's ReputationGate/cache.
 *
 * CONTRACT: MUST NOT make a synchronous network call on the request path (M5 / decision N). An
 * implementation returns a CACHED or FAIL-OPEN verdict only — it consumes F's cachedVerdict(), never
 * a live socket. A fresh per-IP lookup (if the operator enabled checking) happens out-of-band and
 * populates F's cache; this port reads that cache. Inert (always 'unknown') unless the consumer
 * enabled checking AND a key is set (F §4.1).
 *
 * Signal telemetry never rides this request-path lookup (decision T3): it stays strictly read-only.
 */
interface ReputationInterface
{
    /**
     * Cache-first reputation for an actor IP.
     *
     * @param string $ip
     * @return ReputationVerdict cached verdict, or a fail-open 'unknown' when nothing is cached
     */
    public function lookup(string $ip);
}
