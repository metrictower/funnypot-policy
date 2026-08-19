<?php

namespace Funnypot\Policy;

/**
 * Per-rule learn-then-enforce state (design §6, M7). A rule is a single detection signal (an engine
 * matcher class, a cheap-static check, a sacrificial-path pattern). Promotion is human-gated + slow;
 * demotion is automatic + instant. Untyped props + docblocks (typed properties are 7.4+).
 */
final class RuleState
{
    const SHADOW   = 'shadow';   // log-only; action forced to LOG regardless of what the rule wanted
    const TUNING   = 'tuning';   // scoped exclusions compiled; a human approves promotion
    const ENFORCED = 'enforced'; // the rule's intended action applies for real

    /** @var string one of the phase constants */
    private $phase;
    /** @var int epoch seconds the rule entered its current phase (dwell start) */
    private $since;
    /** @var int evaluated-request count accrued in SHADOW */
    private $count;
    /** @var array scoped exclusion tuples [rule_id, path_prefix, param] — never a global disable */
    private $exclusions;
    /** @var bool a human approved the pending promotion (required before ENFORCED) */
    private $humanApproved;

    /**
     * @param string $phase
     * @param int    $since
     * @param int    $count
     * @param array  $exclusions
     * @param bool   $humanApproved
     */
    public function __construct($phase = self::SHADOW, $since = 0, $count = 0, array $exclusions = array(), $humanApproved = false)
    {
        $this->phase = (string) $phase;
        $this->since = (int) $since;
        $this->count = (int) $count;
        $this->exclusions = array_values($exclusions);
        $this->humanApproved = (bool) $humanApproved;
    }

    public function phase()
    {
        return $this->phase;
    }

    public function since()
    {
        return $this->since;
    }

    public function count()
    {
        return $this->count;
    }

    public function exclusions()
    {
        return $this->exclusions;
    }

    public function humanApproved()
    {
        return $this->humanApproved;
    }

    public function isShadow()
    {
        return $this->phase === self::SHADOW;
    }

    public function isEnforced()
    {
        return $this->phase === self::ENFORCED;
    }
}
