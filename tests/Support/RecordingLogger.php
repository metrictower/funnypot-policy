<?php

namespace Funnypot\Policy\Tests\Support;

use Funnypot\Policy\Port\Logger;

/** Captures every log() so a test can assert no signature string / raw payload / secret ever appears. */
final class RecordingLogger implements Logger
{
    /** @var array list of [level, message, context] */
    public $records = array();

    public function log(string $level, string $message, array $context = array())
    {
        $this->records[] = array($level, $message, $context);
    }

    /** Flat concatenation of every message + serialized context, for substring assertions. */
    public function haystack()
    {
        $out = '';
        foreach ($this->records as $r) {
            $out .= $r[0] . ' ' . $r[1] . ' ' . serialize($r[2]) . "\n";
        }

        return $out;
    }
}
