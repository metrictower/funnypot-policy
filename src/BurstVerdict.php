<?php

namespace Funnypot\Policy;

/**
 * FP-0439 — the burst-fuzzing analyzer's output: PURE DATA describing the rate-limit deception the
 * response layer should serve (an HTTP 429/403 with an exponential Retry-After + an ephemeral event id).
 * The adapter turns this into a Decision::deceive(FakeResponse) + the rendered page; this object carries
 * no behaviour and performs no effect (matches the engine's pure-data design). PHP 7.3.
 */
final class BurstVerdict
{
    /** @var int HTTP status to serve (429 Too Many Requests). */
    private $status;
    /** @var int Retry-After header value, seconds (exponential across consecutive breaches). */
    private $retryAfter;
    /** @var string 32-char hex event id, echoed in header + body for correlation. */
    private $eventId;
    /** @var int observed requests in the velocity window (telemetry). */
    private $reqInWindow;
    /** @var int observed decoy hits in the decoy window (telemetry). */
    private $decoyInWindow;

    public function __construct($status, $retryAfter, $eventId, $reqInWindow = 0, $decoyInWindow = 0)
    {
        $this->status = (int) $status;
        $this->retryAfter = (int) $retryAfter;
        $this->eventId = (string) $eventId;
        $this->reqInWindow = (int) $reqInWindow;
        $this->decoyInWindow = (int) $decoyInWindow;
    }

    public function status()
    {
        return $this->status;
    }

    public function retryAfter()
    {
        return $this->retryAfter;
    }

    public function eventId()
    {
        return $this->eventId;
    }

    public function reqInWindow()
    {
        return $this->reqInWindow;
    }

    public function decoyInWindow()
    {
        return $this->decoyInWindow;
    }
}
