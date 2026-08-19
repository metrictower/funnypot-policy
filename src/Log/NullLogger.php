<?php

namespace Funnypot\Policy\Log;

use Funnypot\Policy\Port\Logger;

/** The shipped default Logger: swallows every call (design §2.5). */
final class NullLogger implements Logger
{
    public function log(string $level, string $message, array $context = array())
    {
        // no-op
    }
}
