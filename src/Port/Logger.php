<?php

namespace Funnypot\Policy\Port;

/**
 * PSR-3-shaped log seam (design §2.5) but NOT a require on psr/log (7.3 host, zero hard deps). The
 * engine logs decisions and state transitions; it NEVER logs a canonical signature string, a raw
 * attacker payload verbatim, or a secret (§10). NullLogger ships as the default.
 */
interface Logger
{
    /** @return void */
    public function log(string $level, string $message, array $context = array());
}
