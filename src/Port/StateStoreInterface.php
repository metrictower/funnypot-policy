<?php

namespace Funnypot\Policy\Port;

use Funnypot\Policy\ActorFacts;
use Funnypot\Policy\AggScore;
use Funnypot\Policy\Pin;
use Funnypot\Policy\ReputationVerdict;
use Funnypot\Policy\RuleState;

/**
 * The one persistence seam (design §2.3). The host injects a backing (WP options/transients, Laravel
 * cache/DB, the app's SQLite). The engine only reads/writes through this interface; it never touches a
 * store directly. Reputation-caching is F's own store (behind ReputationInterface), kept separate so the
 * two concerns never share a key namespace.
 */
interface StateStoreInterface
{
    // --- deception-consistency pins + local blocklist (M5) ---

    /** @return Pin|null {action, seed, expiresAt}, or null when no live pin */
    public function getPin(string $ip);

    /** @return void */
    public function setPin(string $ip, string $action, string $seed, int $ttlSeconds);

    /** @return bool local blocklist membership */
    public function isBlocked(string $ip);

    // --- fleet-read: local blacklist mirror (O1) ---

    /**
     * The synced thin blacklist artifact (thin row {score_key, verdict, expires_at}; score_key is an
     * IP, a CIDR, or an ASN — P2/Q1). The PRIMARY fresh-read consulted before any per-IP escalation.
     * Matches the visitor IP by CIDR-CONTAINMENT / ASN-lookup, NOT exact-match (P2/Q2); the caller
     * normalises an IPv6 to its /64 (or the flagged prefix) before the lookup. Most-specific match
     * wins (Q4). Null => nothing covers the IP (escalate).
     *
     * @return ReputationVerdict|null source='mirror', or null when nothing covers the IP
     */
    public function mirrorVerdict(string $ip);

    // --- learn-then-enforce per-rule state (M7) ---

    /** @return RuleState {phase, since, count, exclusions[]} */
    public function ruleState(string $ruleId);

    /** @return void */
    public function putRuleState(string $ruleId, RuleState $s);

    /** @return void SHADOW evaluated-request counter */
    public function bumpRuleEvaluated(string $ruleId, int $n = 1);

    // --- suppression ledger (§9) ---

    /** @return bool true => already seen in the window (dedup) */
    public function seenVerdict(string $dedupKey, int $ttlSeconds);

    /** @return int per-IP alerts counted this window */
    public function incrAlertCount(string $ip, int $windowSeconds);

    /** @return int the collapsed count for this group after buffering */
    public function bufferReport(string $groupKey, array $report, int $ttlSeconds);

    /** @return array drained grouped reports */
    public function takeReportBuffer();

    /** @return AggScore {sources[], total} over the window */
    public function aggregateScore(string $scoreKey, int $windowDays);

    /**
     * The read-time-decay accumulator that feeds the score gate (§9). Applies read-time decay to the
     * stored per-actor value (drifts down without a sweep — the G1 shape), adds $inc, persists, and
     * returns the new decayed score. Store-side decay/persistence mirrors incr()'s store-side windowing.
     *
     * @param string $key            per-actor score key
     * @param int    $inc            the increment for this event (+1 soft / +10 medium / +100 hard-tell)
     * @param int    $baseTtlSeconds the decay time-constant
     * @param int    $capTtlSeconds  the age past which a contribution has fully decayed
     * @return int the decayed score after adding $inc
     */
    public function decayScore(string $key, int $inc, int $baseTtlSeconds, int $capTtlSeconds);

    // --- rolling per-actor counters for the FP heuristic + velocity ---

    /** @return ActorFacts {authSession, loadsAssets, matches30d, firstSeen} */
    public function actorFacts(string $ip);

    /** @return int the counter value after the increment, within the window */
    public function incr(string $counterKey, int $windowSeconds);
}
