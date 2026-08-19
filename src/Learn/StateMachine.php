<?php

namespace Funnypot\Policy\Learn;

use Funnypot\Policy\ActorFacts;
use Funnypot\Policy\Port\Clock;
use Funnypot\Policy\Port\Logger;
use Funnypot\Policy\Port\StateStoreInterface;
use Funnypot\Policy\PolicyConfig;
use Funnypot\Policy\RuleState;

/**
 * Per-rule learn-then-enforce transitions (design §6, M7). ASYMMETRIC: promotion is human-gated and
 * slow (dwell AND volume, then a human approve); demotion is automatic and instant. The evaluate-time
 * gating (a SHADOW rule forces log; the kill-switch demotes all; the day-1 sacrificial carve-out) lives
 * in PolicyEngine; this service drives the STATE changes an admin UI / adapter triggers.
 */
final class StateMachine
{
    /** @var StateStoreInterface */
    private $store;
    /** @var Clock */
    private $clock;
    /** @var PolicyConfig */
    private $config;
    /** @var Logger */
    private $logger;

    public function __construct(StateStoreInterface $store, Clock $clock, PolicyConfig $config, Logger $logger)
    {
        $this->store = $store;
        $this->clock = $clock;
        $this->config = $config;
        $this->logger = $logger;
    }

    /**
     * SHADOW -> TUNING gate: min shadow_days AND min shadow_min_reqs (BOTH — a low-traffic site needs the
     * calendar time; a high-traffic site needs the volume). Neither alone promotes.
     */
    public function eligibleForTuning($ruleId)
    {
        $s = $this->store->ruleState($ruleId);
        if (!$s->isShadow()) {
            return false;
        }
        $learn = $this->config->learn();
        $dwellOk = ($this->clock->now() - $s->since()) >= $learn['shadow_days'] * 86400;
        $volumeOk = $s->count() >= $learn['shadow_min_reqs'];

        return $dwellOk && $volumeOk;
    }

    /** Promote SHADOW -> TUNING when eligible. Returns whether it promoted. */
    public function promoteToTuning($ruleId)
    {
        if (!$this->eligibleForTuning($ruleId)) {
            return false;
        }
        $s = $this->store->ruleState($ruleId);
        $this->store->putRuleState($ruleId, new RuleState(RuleState::TUNING, $this->clock->now(), $s->count(), $s->exclusions(), false));

        return true;
    }

    /**
     * The TUNING FP heuristic: an "otherwise-legit actor" = authenticated session AND clean reputation
     * AND loads page assets AND no other rule matches in 30 days (design §6). A flag on such an actor is
     * an FP candidate.
     */
    public function isOtherwiseLegit(ActorFacts $facts, $cleanReputation)
    {
        return $facts->authSession() && $cleanReputation === true && $facts->loadsAssets() && $facts->matches30d() === 0;
    }

    /**
     * Compile a SCOPED exclusion tuple (rule_id, path_prefix, param) from an otherwise-legit FP — NEVER a
     * global disable (a global disable throws away the rule's value everywhere to fix one path). Returns
     * whether a tuple was compiled.
     */
    public function compileExclusion($ruleId, ActorFacts $facts, $cleanReputation, $pathPrefix, $param)
    {
        if (!$this->isOtherwiseLegit($facts, $cleanReputation)) {
            return false;
        }
        $s = $this->store->ruleState($ruleId);
        $ex = $s->exclusions();
        $ex[] = array('rule_id' => $ruleId, 'path_prefix' => (string) $pathPrefix, 'param' => (string) $param);
        $this->store->putRuleState($ruleId, new RuleState($s->phase(), $s->since(), $s->count(), $ex, $s->humanApproved()));

        return true;
    }

    /** The human approve step required before ENFORCED. */
    public function approve($ruleId)
    {
        $s = $this->store->ruleState($ruleId);
        $this->store->putRuleState($ruleId, new RuleState($s->phase(), $s->since(), $s->count(), $s->exclusions(), true));
    }

    /**
     * TUNING -> ENFORCED: per-rule, one click, only after a human approve (the "zero suspected FPs in the
     * window" precondition is surfaced by the UI). Returns whether it promoted.
     */
    public function promoteToEnforced($ruleId)
    {
        $s = $this->store->ruleState($ruleId);
        if ($s->phase() !== RuleState::TUNING || !$s->humanApproved()) {
            return false; // human gate
        }
        $this->store->putRuleState($ruleId, new RuleState(RuleState::ENFORCED, $this->clock->now(), $s->count(), $s->exclusions(), true));

        return true;
    }

    /**
     * Auto-demote (automatic, instant): an ENFORCED rule that fires on an actor SUBSEQUENTLY PROVEN LEGIT
     * demotes to SHADOW and raises an alert — no human. The asymmetry is the safety property. Returns
     * whether it demoted.
     */
    public function demoteOnProvenLegit($ruleId)
    {
        $s = $this->store->ruleState($ruleId);
        if (!$s->isEnforced()) {
            return false;
        }
        $this->store->putRuleState($ruleId, new RuleState(RuleState::SHADOW, $this->clock->now(), 0, $s->exclusions(), false));
        $this->logger->log('warning', 'rule auto-demoted to shadow on proven-legit actor', array('reason' => 'shadow'));

        return true;
    }

    /** Ship the baseline of known-FP-prone rule ids pre-excluded (the paranoia-level-1 analog, §6). */
    public function applyBaseline()
    {
        foreach ($this->config->learn()['baseline_excluded'] as $ruleId) {
            $ruleId = (string) $ruleId;
            $s = $this->store->ruleState($ruleId);
            $ex = $s->exclusions();
            $ex[] = array('rule_id' => $ruleId, 'path_prefix' => '', 'param' => '', 'baseline' => true);
            $this->store->putRuleState($ruleId, new RuleState($s->phase(), $s->since(), $s->count(), $ex, $s->humanApproved()));
        }
    }
}
