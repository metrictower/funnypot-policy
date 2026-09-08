<?php

namespace Funnypot\Policy;

/**
 * The engine's read of the request bytes (design §2.1), mirroring core's M2 output. The request-evidence
 * axis of §4. Untyped props + docblocks (typed properties are 7.4+).
 *
 * `matched` carries a bool + an OPAQUE signal handle (the rule id) — NEVER a canonical signature string
 * (§10). The engine never sees a nuclei matcher word / CRS rule id / ModSecurity marker.
 */
final class Verdict
{
    // classification (least -> most actionable)
    const CLEAN         = 'clean';
    const AMBIENT       = 'ambient';       // ordinary ambient-path traffic: observe softly by default
    const SUSPICIOUS    = 'suspicious';    // the uncertainty band → never deceive (§5)
    const SCANNER_PROBE = 'scanner-probe'; // counterfactual-404 probe → deceive
    const ATTACK_CLASS  = 'attack-class';  // a specific class, real route → block/deceive per §5

    const SEVERITY_LOW    = 'low';
    const SEVERITY_MEDIUM = 'medium';
    const SEVERITY_HIGH   = 'high';

    /** @var string one of the classification constants */
    private $classification;
    /** @var bool a specific signature matched */
    private $matched;
    /** @var string opaque signal/rule handle — never a signature string */
    private $signal;
    /** @var int cumulative anomaly score (bot-signal starting weights already folded in by core) */
    private $anomalyScore;
    /** @var string one of the SEVERITY_* constants */
    private $severity;
    /** @var bool did this path hit a route that actually exists? (resolved via the SiteProfile oracle) */
    private $onRealRoute;
    /** @var BotSignals the S request-shape signal set */
    private $botSignals;
    /**
     * @var string OPAQUE engine handle. The policy NEVER reads, parses or branches on this — it
     *             carries it so the adapter can hand it back to the engine unchanged.
     */
    private $engineHandle;

    /**
     * @param string          $classification
     * @param bool            $matched
     * @param string          $signal      opaque handle (rule id), never a signature string
     * @param int             $anomalyScore
     * @param string          $severity
     * @param bool            $onRealRoute
     * @param BotSignals|null $botSignals
     * @param string          $engineHandle opaque; the policy only carries it (see engineHandle())
     */
    public function __construct($classification, $matched, $signal, $anomalyScore, $severity, $onRealRoute, $botSignals = null, $engineHandle = '')
    {
        $this->classification = (string) $classification;
        $this->matched = (bool) $matched;
        $this->signal = (string) $signal;
        $this->anomalyScore = (int) $anomalyScore;
        $this->severity = (string) $severity;
        $this->onRealRoute = (bool) $onRealRoute;
        $this->botSignals = $botSignals instanceof BotSignals ? $botSignals : BotSignals::none();
        $this->engineHandle = (string) $engineHandle;
    }

    public function classification()
    {
        return $this->classification;
    }

    public function matched()
    {
        return $this->matched;
    }

    /** The opaque signal handle. */
    public function signal()
    {
        return $this->signal;
    }

    /** The per-rule learn-then-enforce identity (design §6) — the opaque signal handle. */
    public function ruleId()
    {
        return $this->signal;
    }

    public function anomalyScore()
    {
        return $this->anomalyScore;
    }

    public function severity()
    {
        return $this->severity;
    }

    public function onRealRoute()
    {
        return $this->onRealRoute;
    }

    public function botSignals()
    {
        return $this->botSignals;
    }

    /**
     * The engine's own opaque handle for whatever produced this verdict, carried across the policy
     * boundary untouched.
     *
     * The policy MUST NOT read, parse or branch on it — treat it as bytes. It exists solely so an
     * adapter can round-trip an engine's classify() result into its synthesize() call without
     * needing to keep the engine's object graph alive alongside the Verdict.
     *
     * Without it, an adapter has to either memoise the engine's handle against the Verdict (which
     * needs WeakMap, so PHP 8.0+, ruling out WordPress hosts) or re-run classify() a second time
     * and pay double. Both were being done, in different adapters, for the same contract.
     *
     * Empty string when the engine supplies none.
     */
    public function engineHandle()
    {
        return $this->engineHandle;
    }
}
