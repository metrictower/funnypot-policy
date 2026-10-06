<?php

namespace Funnypot\Policy;

/**
 * FP-0439 — adaptive sliding-window burst-fuzzing detector. Mass scanners (ffuf/gobuster/dirsearch/
 * Nikto) flood dozens-to-hundreds of req/s hunting unlinked paths. Dropping the connection or hard-
 * banning ends the engagement early (no full recon/payload harvest); answering every burst wastes the
 * box. This analyzer tracks per-source request velocity + decoy-hit rate over sliding windows and, when
 * a threshold is breached, yields a BurstVerdict telling the response layer to serve a believable edge/
 * WAF rate-limit (HTTP 429/403 + an exponential Retry-After + an event id) that throttles the scanner's
 * throughput while keeping it engaged and telemetry flowing.
 *
 * It does NOT tarpit (a PHP-FPM sleep is a self-DoS — the Decision enum cut tarpit for that reason); the
 * verdict is a fast 429/403 page, never a server-side delay. Pure of I/O: it holds in-memory per-source
 * sliding windows (bounded + LRU-evicted), an injected clock (float seconds) for sub-second velocity, and
 * an injected token generator so the event id is testable. PHP 7.3 (untyped props + docblocks; no arrow
 * fns / typed props / enums).
 */
final class BurstFuzzingAnalyzer
{
    /** Default thresholds (per the ticket): req/s velocity + decoy-hit burst. Configurable via ctor. */
    const DEFAULT_REQ_PER_SEC = 25;      // > this many requests in the 1s window trips velocity
    const DEFAULT_DECOY_BURST = 12;      // > this many decoy hits in DECOY_WINDOW_SECS trips the decoy burst
    const VELOCITY_WINDOW_SECS = 1.0;
    const DECOY_WINDOW_SECS = 5.0;
    const MAX_TRACKED = 4096;            // LRU cap on tracked sources — bounds memory
    const MAX_SAMPLES = 512;             // per-source ring cap — a flood can't grow one window unbounded
    /** Exponential Retry-After ladder (seconds), indexed by consecutive-breach count. */
    const RETRY_LADDER = array(3, 6, 12, 30, 60);

    /** @var int */
    private $reqPerSec;
    /** @var int */
    private $decoyBurst;
    /** @var callable returns float epoch seconds */
    private $clock;
    /** @var callable returns a 32-char hex event id */
    private $tokenGen;
    /**
     * @var array<string,array{req:float[], decoy:float[], breaches:int, last:float}>
     * per-source: request + decoy-hit timestamps, current Retry-After ladder level, last-breach time, last-touch.
     */
    private $sources = array();

    public function __construct($reqPerSec = self::DEFAULT_REQ_PER_SEC, $decoyBurst = self::DEFAULT_DECOY_BURST, $clock = null, $tokenGen = null)
    {
        $this->reqPerSec = (int) $reqPerSec;
        $this->decoyBurst = (int) $decoyBurst;
        $this->clock = $clock !== null ? $clock : function () {
            return microtime(true);
        };
        $this->tokenGen = $tokenGen !== null ? $tokenGen : function () {
            return bin2hex(random_bytes(16));
        };
    }

    /**
     * Record one request from $source (an IP or CIDR key) and return a BurstVerdict if it breaches a
     * threshold, else null. $isDecoyHit marks a distinct-404/decoy-path hit (the fuzzing signature).
     *
     * @return BurstVerdict|null
     */
    public function observe($source, $isDecoyHit = false)
    {
        $now = (float) call_user_func($this->clock);
        $this->ensure($source, $now);
        $s = &$this->sources[$source];
        $s['last'] = $now;

        $s['req'][] = $now;
        if ($isDecoyHit) {
            $s['decoy'][] = $now;
        }
        // Prune outside the widest window, and cap the rings so a sustained flood can't grow memory.
        $s['req'] = $this->within($s['req'], $now, self::DECOY_WINDOW_SECS);
        $s['decoy'] = $this->within($s['decoy'], $now, self::DECOY_WINDOW_SECS);

        $reqInSec = count($this->within($s['req'], $now, self::VELOCITY_WINDOW_SECS));
        $decoyInWindow = count($s['decoy']);

        if ($reqInSec > $this->reqPerSec || $decoyInWindow > $this->decoyBurst) {
            // Escalate the Retry-After ladder only when the source keeps flooding into a NEW velocity
            // window (i.e. it ignored the prior Retry-After and came back still flooding) — never
            // per-request, so a single fast burst is ONE level (3s), and a source that keeps hammering
            // across windows climbs 6s/12s/30s/60s. Within one window the level holds.
            $maxLevel = count(self::RETRY_LADDER) - 1;
            if ($s['lastBreachAt'] !== 0.0 && ($now - $s['lastBreachAt']) >= self::VELOCITY_WINDOW_SECS) {
                $s['level'] = min($s['level'] + 1, $maxLevel);
            }
            $s['lastBreachAt'] = $now;
            $retryAfter = self::RETRY_LADDER[min($s['level'], $maxLevel)];
            // The response layer renders the body (JSON 429 for API scanners, branded 403 page for
            // browser fuzzers); the verdict carries the shape + knobs only.
            return new BurstVerdict(429, $retryAfter, (string) call_user_func($this->tokenGen), $reqInSec, $decoyInWindow);
        }

        // A non-breaching request from a source that has gone quiet (no breach within a cooldown) cools
        // the ladder back to level 0, so Retry-After de-escalates rather than sticking at 60s forever.
        if ($s['level'] > 0 && $s['lastBreachAt'] !== 0.0 && ($now - $s['lastBreachAt']) >= self::DECOY_WINDOW_SECS) {
            $s['level'] = 0;
            $s['lastBreachAt'] = 0.0;
        }

        return null;
    }

    /** Timestamps within $window seconds of $now, newest-order preserved; also caps to MAX_SAMPLES. */
    private function within(array $stamps, $now, $window)
    {
        $cut = $now - $window;
        $kept = array();
        foreach ($stamps as $t) {
            if ($t >= $cut) {
                $kept[] = $t;
            }
        }
        if (count($kept) > self::MAX_SAMPLES) {
            $kept = array_slice($kept, -self::MAX_SAMPLES);
        }

        return $kept;
    }

    private function ensure($source, $now)
    {
        if (isset($this->sources[$source])) {
            return;
        }
        if (count($this->sources) >= self::MAX_TRACKED) {
            $oldestKey = null;
            $oldestAt = INF;
            foreach ($this->sources as $k => $v) {
                if ($v['last'] < $oldestAt) {
                    $oldestAt = $v['last'];
                    $oldestKey = $k;
                }
            }
            if ($oldestKey !== null) {
                unset($this->sources[$oldestKey]);
            }
        }
        $this->sources[$source] = array('req' => array(), 'decoy' => array(), 'level' => 0, 'lastBreachAt' => 0.0, 'last' => $now);
    }

    /** Tracked-source count (tests / introspection). */
    public function trackedSources()
    {
        return count($this->sources);
    }
}
