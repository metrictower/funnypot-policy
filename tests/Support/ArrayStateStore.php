<?php

namespace Funnypot\Policy\Tests\Support;

use Funnypot\Policy\ActorFacts;
use Funnypot\Policy\AggScore;
use Funnypot\Policy\Net;
use Funnypot\Policy\Pin;
use Funnypot\Policy\Port\Clock;
use Funnypot\Policy\Port\StateStoreInterface;
use Funnypot\Policy\ReputationVerdict;
use Funnypot\Policy\RuleState;

/**
 * In-memory StateStoreInterface backing for tests, driven by the injected FixedClock so every TTL/decay/
 * window is deterministic. The mirror matches by CIDR-CONTAINMENT / ASN-lookup, never exact-match
 * (P2/Q2), normalises an IPv6 to its /64 before lookup, and applies most-specific-match-wins (Q4).
 * Optional throw flag drives the fail-safe matrix.
 */
final class ArrayStateStore implements StateStoreInterface
{
    /** @var Clock */
    private $clock;

    /** @var array ip => Pin */
    private $pins = array();
    /** @var array ip => true */
    private $blocked = array();
    /** @var array list of [scoreKey, verdict, expiresAt, usageType] mirror rows */
    private $mirror = array();
    /** @var array ip => asn (so mirror ASN rows can match by the visitor's ASN) */
    private $ipAsn = array();
    /** @var array ruleId => RuleState */
    private $ruleStates = array();
    /** @var array dedupKey => expiresAt */
    private $seen = array();
    /** @var array key => list of timestamps (windowed counters) */
    private $counters = array();
    /** @var array groupKey => list of reports */
    private $buffers = array();
    /** @var array scoreKey => list of [source, score, at] */
    private $aggregates = array();
    /** @var array key => [value, ts] decay accumulator state */
    private $scores = array();
    /** @var array ip => ActorFacts */
    private $actorFacts = array();

    /** @var bool */
    public $throwOnAccess = false;

    public function __construct(Clock $clock)
    {
        $this->clock = $clock;
    }

    private function guard()
    {
        if ($this->throwOnAccess) {
            throw new \RuntimeException('store boom');
        }
    }

    // --- pins + blocklist ---

    public function getPin(string $ip)
    {
        $this->guard();
        if (!isset($this->pins[$ip])) {
            return null;
        }
        $pin = $this->pins[$ip];
        if ($pin->expiresAt() <= $this->clock->now()) {
            unset($this->pins[$ip]);

            return null;
        }

        return $pin;
    }

    public function setPin(string $ip, string $action, string $seed, int $ttlSeconds)
    {
        $this->guard();
        $this->pins[$ip] = new Pin($action, $seed, $this->clock->now() + $ttlSeconds);
    }

    public function isBlocked(string $ip)
    {
        $this->guard();

        return isset($this->blocked[$ip]);
    }

    public function block(string $ip)
    {
        $this->blocked[$ip] = true;

        return $this;
    }

    // --- local blacklist mirror (O1) ---

    /**
     * Seed a thin mirror row. $scoreKey is an IP, a CIDR (v4/v6), or an ASN token (e.g. 'AS64500').
     */
    public function seedMirror(string $scoreKey, string $verdict, $expiresAt = null, $usageType = null)
    {
        $this->mirror[] = array($scoreKey, $verdict, $expiresAt, $usageType);

        return $this;
    }

    /** Associate a visitor IP with an ASN so ASN mirror rows can match it. */
    public function seedIpAsn(string $ip, string $asn)
    {
        $this->ipAsn[$ip] = $asn;

        return $this;
    }

    public function mirrorVerdict(string $ip)
    {
        $this->guard();
        $now = $this->clock->now();
        $best = null;
        $bestPrefix = -1;

        // Normalise an IPv6 to its /64 before matching (P2) — a /128-rotating attacker cannot evade a
        // /64 (or coarser) mirror row.
        $normalised = Net::normaliseV6($ip);
        $asn = isset($this->ipAsn[$ip]) ? $this->ipAsn[$ip] : null;

        foreach ($this->mirror as $row) {
            list($scoreKey, $verdict, $expiresAt, $usageType) = $row;
            if ($expiresAt !== null && $expiresAt <= $now) {
                continue; // expired row
            }

            if (self::isAsnKey($scoreKey)) {
                // ASN rows have no prefix length; treat as the coarsest match (prefix 0) so an exact IP
                // or CIDR row still wins most-specific.
                if ($asn !== null && strcasecmp($scoreKey, $asn) === 0 && $bestPrefix < 0) {
                    $best = new ReputationVerdict($verdict, null, ReputationVerdict::SOURCE_MIRROR, $usageType);
                    $bestPrefix = 0;
                }
                continue;
            }

            $prefix = Net::containment($scoreKey, $normalised);
            if ($prefix < 0) {
                // A row keyed by an exact IPv6 /128 still matches the un-normalised address.
                $prefix = Net::containment($scoreKey, $ip);
            }
            if ($prefix >= 0 && $prefix >= $bestPrefix) {
                $best = new ReputationVerdict($verdict, null, ReputationVerdict::SOURCE_MIRROR, $usageType);
                $bestPrefix = $prefix;
            }
        }

        return $best;
    }

    private static function isAsnKey(string $key)
    {
        return stripos($key, 'AS') === 0 && ctype_digit(substr($key, 2));
    }

    // --- rule state ---

    public function ruleState(string $ruleId)
    {
        $this->guard();
        if (isset($this->ruleStates[$ruleId])) {
            return $this->ruleStates[$ruleId];
        }

        return new RuleState(RuleState::SHADOW, $this->clock->now(), 0);
    }

    public function putRuleState(string $ruleId, RuleState $s)
    {
        $this->guard();
        $this->ruleStates[$ruleId] = $s;
    }

    public function bumpRuleEvaluated(string $ruleId, int $n = 1)
    {
        $this->guard();
        $s = $this->ruleState($ruleId);
        $this->ruleStates[$ruleId] = new RuleState(
            $s->phase(),
            $s->since(),
            $s->count() + $n,
            $s->exclusions(),
            $s->humanApproved()
        );
    }

    // --- suppression ledger ---

    public function seenVerdict(string $dedupKey, int $ttlSeconds)
    {
        $this->guard();
        $now = $this->clock->now();
        if (isset($this->seen[$dedupKey]) && $this->seen[$dedupKey] > $now) {
            return true;
        }
        $this->seen[$dedupKey] = $now + $ttlSeconds;

        return false;
    }

    public function incrAlertCount(string $ip, int $windowSeconds)
    {
        return $this->incr('alert:' . $ip, $windowSeconds);
    }

    public function bufferReport(string $groupKey, array $report, int $ttlSeconds)
    {
        $this->guard();
        if (!isset($this->buffers[$groupKey])) {
            $this->buffers[$groupKey] = array();
        }
        $this->buffers[$groupKey][] = $report;

        return count($this->buffers[$groupKey]);
    }

    public function takeReportBuffer()
    {
        $this->guard();
        $out = $this->buffers;
        $this->buffers = array();

        return $out;
    }

    public function aggregateScore(string $scoreKey, int $windowDays)
    {
        $this->guard();
        $cutoff = $this->clock->now() - ($windowDays * 86400);
        $sources = array();
        $total = 0;
        if (isset($this->aggregates[$scoreKey])) {
            foreach ($this->aggregates[$scoreKey] as $entry) {
                list($source, $score, $at) = $entry;
                if ($at >= $cutoff) {
                    $sources[] = $source;
                    $total += $score;
                }
            }
        }

        return new AggScore($sources, $total);
    }

    /** Seed an aggregate contribution (fleet-populated in production; seeded in tests). */
    public function seedAggregate(string $scoreKey, string $source, int $score, $at = null)
    {
        if ($at === null) {
            $at = $this->clock->now();
        }
        if (!isset($this->aggregates[$scoreKey])) {
            $this->aggregates[$scoreKey] = array();
        }
        $this->aggregates[$scoreKey][] = array($source, $score, (int) $at);

        return $this;
    }

    public function decayScore(string $key, int $inc, int $baseTtlSeconds, int $capTtlSeconds)
    {
        $this->guard();
        $now = $this->clock->now();
        $value = 0.0;
        if (isset($this->scores[$key])) {
            list($prev, $ts) = $this->scores[$key];
            $elapsed = $now - $ts;
            if ($elapsed < $capTtlSeconds && $baseTtlSeconds > 0) {
                // Read-time exponential decay toward zero (drifts down without a sweep).
                $value = $prev * exp(-$elapsed / $baseTtlSeconds);
            } else {
                $value = 0.0;
            }
        }
        $value += $inc;
        $this->scores[$key] = array($value, $now);

        return (int) floor($value);
    }

    // --- actor facts + counters ---

    public function actorFacts(string $ip)
    {
        $this->guard();

        return isset($this->actorFacts[$ip]) ? $this->actorFacts[$ip] : new ActorFacts();
    }

    public function setActorFacts(string $ip, ActorFacts $facts)
    {
        $this->actorFacts[$ip] = $facts;

        return $this;
    }

    public function incr(string $counterKey, int $windowSeconds)
    {
        $this->guard();
        $now = $this->clock->now();
        if (!isset($this->counters[$counterKey])) {
            $this->counters[$counterKey] = array();
        }
        // Drop timestamps outside the rolling window, then record this hit.
        $cutoff = $now - $windowSeconds;
        $kept = array();
        foreach ($this->counters[$counterKey] as $ts) {
            if ($ts > $cutoff) {
                $kept[] = $ts;
            }
        }
        $kept[] = $now;
        $this->counters[$counterKey] = $kept;

        return count($kept);
    }
}
