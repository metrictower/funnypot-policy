<?php

namespace Funnypot\Policy;

use Funnypot\Policy\Port\Clock;
use Funnypot\Policy\Port\EvaluatorInterface;
use Funnypot\Policy\Port\GeoIpInterface;
use Funnypot\Policy\Port\Logger;
use Funnypot\Policy\Port\ReputationInterface;
use Funnypot\Policy\Port\StateStoreInterface;
use Funnypot\Policy\Report\Suppressor;

/**
 * The decision brain (design §4). Runs the fixed, cheapest-first precedence ladder and returns exactly
 * one Decision — pure data, zero side effects on the response (M3). The only writes it performs are
 * through the injected StateStore (pins, counters), never a direct effect.
 *
 * evaluate() NEVER throws on the request path: every port fault degrades to Decision::allow (invariant
 * 2). Reputation is a modifier, never primary (§4). Deceive is fenced to counterfactual-404 or a
 * specific matched signature past threshold on a real route — never the uncertainty band (§5).
 */
final class PolicyEngine
{
    /** action rank for raise/cap math */
    private static $rank = array(
        Decision::ALLOW => 0,
        Decision::LOG => 1,
        Decision::BLOCK => 2,
        Decision::DECEIVE => 3,
    );

    /** cheap-static exact-match tool UAs — the attacker's own declared tool, not a honeypot signature */
    private static $scannerUas = array('sqlmap', 'nmap', 'nikto', 'masscan', 'nuclei', 'zgrab', 'wpscan');

    /** fusion threshold: the composite scrutiny (bot-signals + datacenter + country) that raises to log */
    const SCRUTINY_THRESHOLD = 2;

    /** @var EvaluatorInterface */
    private $evaluator;
    /** @var ReputationInterface */
    private $reputation;
    /** @var StateStoreInterface */
    private $store;
    /** @var GeoIpInterface */
    private $geo;
    /** @var Clock */
    private $clock;
    /** @var Logger */
    private $logger;
    /** @var PolicyConfig */
    private $config;
    /** @var string */
    private $siteSalt;
    /** @var Suppressor */
    private $suppressor;
    /** @var string the reporting source id stamped on emitted ReportIntents */
    private $source;

    public function __construct(
        EvaluatorInterface $evaluator,
        ReputationInterface $reputation,
        StateStoreInterface $store,
        GeoIpInterface $geo,
        Clock $clock,
        Logger $logger,
        PolicyConfig $config,
        $siteSalt = '',
        $source = 'honeypot'
    ) {
        $this->evaluator = $evaluator;
        $this->reputation = $reputation;
        $this->store = $store;
        $this->geo = $geo;
        $this->clock = $clock;
        $this->logger = $logger;
        $this->config = $config;
        $this->siteSalt = (string) $siteSalt;
        $this->source = (string) $source;
        $this->suppressor = new Suppressor($store, $clock, $config, $logger);
    }

    /**
     * The single entry point (design §4). Returns a Decision the adapter executes.
     *
     * FAIL-SAFE (invariant 2): this NEVER throws on the request path. EVERY port fault — an evaluator/
     * synthesize throw, a store throw (the highest-probability site — the store is read on every request
     * at precedence step 2), a reputation throw, a geoip throw, a logger/clock throw — degrades to
     * Decision::allow. A policy fault can only ever fail OPEN to the real app; it is never a 5xx (itself a
     * tell) and never an uncaught throw.
     */
    public function evaluate(RequestEvidence $e, SiteProfile $p)
    {
        try {
            return $this->evaluatePositions($e, $p);
        } catch (\Throwable $ex) {
            $this->safeLog('policy failed open', $ex);

            return Decision::allow('failsafe');
        }
    }

    /**
     * Run the configured position(s). For the `both` posture the request is evaluated at the BEFORE
     * position and, only if that fell through to a plain allow, again at the FALLBACK position (M4). The
     * cheap gates short-circuit hard, so the worst-case double run stays cheap; an actionable before
     * result (or a hard allowlist exempt) short-circuits without the second pass.
     */
    private function evaluatePositions(RequestEvidence $e, SiteProfile $p)
    {
        $before = $this->config->positionEnabled(PolicyConfig::POSITION_BEFORE);
        $fallback = $this->config->positionEnabled(PolicyConfig::POSITION_FALLBACK);

        if ($before && $fallback) {
            $d = $this->pass($e, $p, PolicyConfig::POSITION_BEFORE);
            if ($d->action() === Decision::ALLOW && $d->reason() === 'allow') {
                return $this->pass($e, $p, PolicyConfig::POSITION_FALLBACK); // nothing acted before -> the 404 fallback
            }

            return $d; // actionable, or a hard allowlist/self/safe exempt -> no double-run
        }
        if ($before) {
            return $this->pass($e, $p, PolicyConfig::POSITION_BEFORE);
        }

        return $this->pass($e, $p, PolicyConfig::POSITION_FALLBACK);
    }

    /** Log without ever letting a logger fault escape the request path. */
    private function safeLog($message, $ex)
    {
        try {
            $this->logger->log('error', $message, array('reason' => 'failsafe'));
        } catch (\Throwable $ignored) {
            // a logger fault must never turn a fail-open into a 500
        }
    }

    /** One ladder pass at a given position, returning on the first gate that decides. */
    private function pass(RequestEvidence $e, SiteProfile $p, $position)
    {
        $ip = $e->ip();

        // STEP 1 — ALLOWLIST (hard override; beats reputation, beats everything below).
        $allow = $this->allowlistReason($e);
        if ($allow !== null) {
            return Decision::allow($allow);
        }

        // STEP 2 — LOCAL PIN / BLOCKLIST.
        $pin = $this->store->getPin($ip);
        if ($pin !== null) {
            return $this->replayPin($pin, $e, $p);
        }
        if ($this->store->isBlocked($ip)) {
            if ($this->protectMode($position)) {
                return $this->withReport(Decision::block(403, 'blocklist'), $e, null, Suppressor::SEV_MEDIUM);
            }

            return $this->withReport($this->deceiveDecision($e, $p, $this->probeVerdict($e, $p), 'blocklist'), $e, null, Suppressor::SEV_MEDIUM);
        }

        // STEP 3 — CHEAP STATIC (no engine call): sacrificial path OR exact-match tool UA.
        if ($p->isSacrificialPath($e->path()) && $p->routeExists($e->path()) === false) {
            // Counterfactual-404 → day-1 auto-enforced deception (§6).
            return $this->withReport($this->deceiveDecision($e, $p, $this->probeVerdict($e, $p), 'sacrificial-path'), $e, null, Suppressor::SEV_MEDIUM);
        }
        if ($this->isScannerUa($e)) {
            if ($this->protectMode($position)) {
                return $this->withReport(Decision::block(403, 'malicious-ua'), $e, null, Suppressor::SEV_HARD);
            }
            if ($p->routeExists($e->path()) === false) {
                return $this->withReport($this->deceiveDecision($e, $p, $this->probeVerdict($e, $p), 'malicious-ua'), $e, null, Suppressor::SEV_HARD);
            }

            return $this->withReport(Decision::log('malicious-ua'), $e, null, Suppressor::SEV_MEDIUM);
        }

        // STEP 3a — COUNTRY GATE (local GeoIP, no network call). A cheap-static gate.
        $countrySuspicion = false;
        $countryOutcome = $this->countryGate($e, $position);
        if ($countryOutcome instanceof Decision) {
            return $countryOutcome; // deceive/block acted immediately
        }
        if ($countryOutcome === true) {
            $countrySuspicion = true; // modifier: armed scrutiny, fall through to steps 4/5
        }

        // STEPS 4 + 5 — reputation modifier + engine classify, combined under the §4/§5 rules.
        return $this->combineAxes($e, $p, $position, $countrySuspicion);
    }

    // -----------------------------------------------------------------------------------------------
    // Step 1 — allowlist
    // -----------------------------------------------------------------------------------------------

    /**
     * The allowlist / self-ip / safe-path hard override (design §4 step 1, re-checked at every mutating
     * point per §9). Returns a reason label on a match, else null. Matched by CONTAINMENT / ASN-lookup
     * (P2/Q2/Q4): a good /24 inside a listed bad ASN/range is exempt.
     */
    public function allowlistReason(RequestEvidence $e)
    {
        $al = $this->config->allowlist();
        $ip = $e->ip();

        if (in_array($ip, $this->config->selfIps(), true)) {
            return 'self-ip';
        }
        if (in_array($ip, $al['ips'], true)) {
            return 'allowlist';
        }
        foreach ($al['cidrs'] as $cidr) {
            if (Net::contains($cidr, $ip)) {
                return 'allowlist';
            }
        }
        $asn = $e->asn();
        if ($asn !== null && $asn !== '') {
            foreach ($al['asns'] as $a) {
                if (strcasecmp((string) $a, $asn) === 0) {
                    return 'allowlist';
                }
            }
        }
        if ($this->pathMatches($e->path(), $al['safe_paths'])) {
            return 'safe-path';
        }

        return null;
    }

    // -----------------------------------------------------------------------------------------------
    // Step 2 — pin replay
    // -----------------------------------------------------------------------------------------------

    /** Replay a pinned action with the pinned seed (deception consistency, M5). */
    private function replayPin(Pin $pin, RequestEvidence $e, SiteProfile $p)
    {
        if ($pin->action() === Decision::DECEIVE) {
            $fake = $this->evaluator->synthesize($this->probeVerdict($e, $p), $p, $pin->seed());

            return Decision::deceive($fake, null, 'pin');
        }
        if ($pin->action() === Decision::BLOCK) {
            return Decision::block(403, 'pin');
        }
        if ($pin->action() === Decision::LOG) {
            return Decision::log('pin');
        }

        return Decision::allow('pin');
    }

    // -----------------------------------------------------------------------------------------------
    // Step 3a — country gate
    // -----------------------------------------------------------------------------------------------

    /**
     * @return Decision|bool|null a Decision when the gate acts (deceive/block); true when it armed the
     *                            score modifier (fall through); null when it did not match / is disabled
     */
    private function countryGate(RequestEvidence $e, $position)
    {
        $co = $this->config->country();
        if (!$co['enabled']) {
            return null; // disabled -> geo.country is never called
        }
        $country = $this->geo->country($e->ip());
        if ($country === null) {
            return null; // geo miss -> fall through, never block on a miss (R4)
        }
        $listed = in_array(strtoupper($country), $co['countries'], true);
        // deny-list: listed countries are acted on. allow-list posture: NON-listed are acted on.
        $matched = ($co['mode'] === 'allow') ? !$listed : $listed;
        if (!$matched) {
            return null;
        }

        if ($co['action'] === 'deceive') {
            return $this->withReport($this->deceiveDecision($e, null, $this->probeVerdict($e, null), 'country'), $e, null, Suppressor::SEV_SOFT);
        }
        if ($co['action'] === 'block' && $this->protectMode($position)) {
            // Hard block is an explicit opt-in; the honeypot posture prefers score/deceive over block
            // (a country block is a tell — R3/M6), so honeypot-mode degrades to the score modifier.
            return $this->withReport(Decision::block(403, 'country'), $e, null, Suppressor::SEV_SOFT);
        }

        // DEFAULT 'modifier' (and honeypot-mode 'block'): raise scrutiny, arm the reputation trigger.
        $this->logger->log('debug', 'country-modifier armed scrutiny', array('reason' => 'country'));

        return true;
    }

    // -----------------------------------------------------------------------------------------------
    // Steps 4 + 5 — the two-axis combination
    // -----------------------------------------------------------------------------------------------

    private function combineAxes(RequestEvidence $e, SiteProfile $p, $position, $countrySuspicion)
    {
        // STEP 4 — reputation: mirror-first, then cache-first (never a sync network call, M5/N).
        $rep = $this->reputationFor($e);

        // STEP 5 — classify (LAST, the expensive gate). Produces the request-evidence axis + botSignals.
        $verdict = $this->evaluator->classify($e, $p);
        $band = $verdict->classification();
        $counterfactual404 = ($verdict->onRealRoute() === false);

        // --- base action from the configured band ceiling ---
        $action = $this->config->actionFor($band);
        $reason = $this->bandReason($band);

        // --- §5 deceive fence: deceive survives only where the counterfactual is a 404, or on a real
        //     route past the block threshold via a SPECIFIC matched signature (never anomaly alone). ---
        $earnedDeceive = false;
        if ($action === Decision::DECEIVE) {
            $specificPastThreshold = $verdict->matched() && $verdict->severity() === Verdict::SEVERITY_HIGH;
            if ($counterfactual404 || $specificPastThreshold) {
                $earnedDeceive = true;
            } else {
                $action = $this->protectMode($position) ? Decision::BLOCK : Decision::LOG;
                $reason = 'suspicious';
            }
        }

        // --- reputation modifier (rules 1-3). Never primary; never deceive on reputation alone. ---
        // The CONTENT axis (after the §5 fence) is captured first: reputation may only MODIFY it, never
        // originate an escalation. A clean-content request is therefore never blocked on reputation alone.
        $contentRank = $this->rankOf($action);
        if ($rep->isMalicious()) {
            // A known-bad actor on an innocuous request is at least observed (rule 3 default floor: log).
            if ($this->rankOf($action) < $this->rankOf(Decision::LOG)) {
                $action = Decision::LOG;
                $reason = 'reputation-modifier';
            }
            // Promote an ALREADY-content-suspicious log to block (rule 1) — only when the operator opted
            // in AND at the BEFORE position (rules 1-3), never a deceive. Clean content (contentRank <
            // LOG) is never escalated to block: reputation is not primary.
            if ($contentRank >= $this->rankOf(Decision::LOG)
                && $this->reputationBlockEligible($rep, $position)
                && $this->rankOf($action) < $this->rankOf(Decision::BLOCK)
            ) {
                $action = Decision::BLOCK;
                $reason = 'reputation-block';
            }
        }

        // --- country + bot-signal composite scrutiny (modifiers; raise allow->log only, never higher) ---
        $scrutiny = $this->compositeScrutiny($e, $verdict, $rep, $countrySuspicion);
        if ($scrutiny >= self::SCRUTINY_THRESHOLD && $this->rankOf($action) < $this->rankOf(Decision::LOG)) {
            $action = Decision::LOG;
            $reason = 'bot-signal-composite';
        }

        // --- posture/position ceiling cap. An EARNED deceive bypasses the cap except at honeypot-before
        //     (which observes before, acting only at the fallback). ---
        if (!($action === Decision::DECEIVE && $earnedDeceive && $this->allowEarnedDeceive($position))) {
            $ceiling = $this->config->ceiling($position);
            if ($this->rankOf($action) > $this->rankOf($ceiling)) {
                $action = $ceiling;
                $reason = $this->capReason($ceiling, $reason);
            }
        }

        // --- learn-then-enforce gate: a real-route rule not yet ENFORCED is held to log (SHADOW/TUNING).
        //     Counterfactual-404 rules auto-enforce (day-1 carve-out, §6). ---
        if ($this->rulePhaseForced($verdict->ruleId(), $counterfactual404) && $this->rankOf($action) > $this->rankOf(Decision::LOG)) {
            $action = Decision::LOG;
            $reason = 'shadow';
        }

        // --- default-install posture (§7): at the FALLBACK position, every otherwise-unmatched request
        //     is deceived. FP-free by construction — a request that reached the 404 fallback had no real
        //     route, so the counterfactual is a 404. ---
        if ($position === PolicyConfig::POSITION_FALLBACK && $action === Decision::ALLOW && $counterfactual404) {
            $action = Decision::DECEIVE;
            $reason = 'fallback-deceive';
        }

        $decision = $this->buildDecision($action, $e, $p, $verdict, $reason);

        return $this->withReport($decision, $e, $verdict, $this->severityFor($verdict, $action));
    }

    /** mirror-first (O1, always consulted), then cache-first per-IP only if reputation checking is on. */
    private function reputationFor(RequestEvidence $e)
    {
        $mirror = $this->store->mirrorVerdict($e->ip());
        if ($mirror !== null) {
            return $mirror;
        }
        $rep = $this->config->reputation();
        if ($rep['enabled']) {
            return $this->reputation->lookup($e->ip());
        }

        return ReputationVerdict::absent();
    }

    private function reputationBlockEligible(ReputationVerdict $rep, $position)
    {
        $r = $this->config->reputation();
        if (!$r['enabled']) {
            return false;
        }
        if (!in_array($rep->verdict(), $r['block_verdicts'], true)) {
            return false;
        }
        if ($r['min_block_score'] !== null && ($rep->score() === null || $rep->score() < $r['min_block_score'])) {
            return false;
        }

        // Never block on reputation alone by default, and only at the BEFORE (protect-mode) position.
        return $this->protectMode($position);
    }

    /**
     * The composite scrutiny (S2/S3): bot-signal weak count + a datacenter usage-type + a country
     * modifier. FP guards apply FIRST (S5) — an exempt/allowlisted actor's bot-signals are zeroed. This
     * is a modifier only; a single weak signal never decides.
     */
    private function compositeScrutiny(RequestEvidence $e, Verdict $verdict, ReputationVerdict $rep, $countrySuspicion)
    {
        $bot = $this->botScrutiny($e, $verdict);
        $score = $bot;
        if ($rep->usageType() === 'datacenter') {
            $score += 1;
        }
        if ($countrySuspicion) {
            $score += 1;
        }

        return $score;
    }

    /** The bot-signal contribution, zeroed for exempt/disabled actors (S5 FP-guards-first). */
    private function botScrutiny(RequestEvidence $e, Verdict $verdict)
    {
        $b = $this->config->botSignals();
        if (!$b['enabled']) {
            return 0;
        }
        if ($this->isExemptUa($e, $b['exempt_uas']) || $this->pathMatches($e->path(), $b['exempt_paths'])) {
            return 0; // carved out specifically — a legit no-header client is not counted
        }

        return $verdict->botSignals()->weakSignalCount();
    }

    // -----------------------------------------------------------------------------------------------
    // Learn-then-enforce gate (the evaluate-time half; transitions live in Learn\StateMachine)
    // -----------------------------------------------------------------------------------------------

    /** True when a real-route rule that is not yet ENFORCED must be held to log (SHADOW/TUNING). */
    private function rulePhaseForced($ruleId, $counterfactual404)
    {
        if ($counterfactual404) {
            return false; // day-1 carve-out: counterfactual-404 rules auto-enforce (§6)
        }
        // Global kill-switch: every real-route rule is demoted to SHADOW at once (incident response, §6).
        if ($this->config->learn()['kill_switch']) {
            return true;
        }
        if ($ruleId === '') {
            return false; // no rule => clean/allow band, nothing to hold
        }
        $state = $this->store->ruleState($ruleId);
        if ($state->phase() === RuleState::SHADOW) {
            // Count this evaluated request toward the shadow promotion volume gate (§6).
            $this->store->bumpRuleEvaluated($ruleId);
        }

        return $state->phase() !== RuleState::ENFORCED;
    }

    // -----------------------------------------------------------------------------------------------
    // Decision construction + deception seed/pin (M5)
    // -----------------------------------------------------------------------------------------------

    private function buildDecision($action, RequestEvidence $e, SiteProfile $p, Verdict $verdict, $reason)
    {
        if ($action === Decision::DECEIVE) {
            return $this->deceiveDecision($e, $p, $verdict, $reason);
        }
        if ($action === Decision::BLOCK) {
            return Decision::block(403, $reason);
        }
        if ($action === Decision::LOG) {
            return Decision::log($reason);
        }

        return Decision::allow('allow');
    }

    /**
     * Build a deceive Decision: derive the deterministic seed, synthesize the fake, and PIN the actor so
     * a later request replays the identical action + seed (M5 deception-consistency, the anti-unmask
     * property). $profile may be null for the cheap-static/country paths that have no SiteProfile handy.
     */
    private function deceiveDecision(RequestEvidence $e, $profile, Verdict $verdict, $reason)
    {
        $seed = $this->seedFor($e);
        $fake = $this->evaluator->synthesize($verdict, $profile instanceof SiteProfile ? $profile : new SiteProfile(''), $seed);
        $ttl = $this->config->pin()['ttl_seconds'];
        $this->store->setPin($e->ip(), Decision::DECEIVE, $seed, $ttl);

        return Decision::deceive($fake, $ttl, $reason);
    }

    /**
     * Emit a ReportIntent on an actionable Decision (§9). The Suppressor applies the backstops + the
     * 4-layer suppression; below the score gate it returns null (recorded, not alerted) and the Decision
     * simply carries no report. A scoring/store fault here NEVER changes the action (a report failure is
     * not a reason to downgrade a block to allow) — it just drops the report.
     */
    private function withReport(Decision $d, RequestEvidence $e, $verdict, $severity)
    {
        if ($d->action() === Decision::ALLOW) {
            return $d;
        }
        try {
            $bot = $verdict instanceof Verdict ? $verdict->botSignals() : null;
            $anomaly = $verdict instanceof Verdict ? $verdict->anomalyScore() : 0;
            $intent = $this->suppressor->consider($e->ip(), $d->action(), $this->source, $severity, array(
                'path' => $e->path(),
                'asn' => $e->asn(),
                'botSignals' => $bot,
                'anomaly' => $anomaly,
            ));
            if ($intent === null) {
                return $d;
            }

            return $d->withReport($intent);
        } catch (\Throwable $ignored) {
            return $d;
        }
    }

    /** Map a decision to a suppression severity: an unambiguous exploit is a hard tell (§9). */
    private function severityFor($verdict, $action)
    {
        if ($verdict instanceof Verdict && $verdict->matched() && $verdict->severity() === Verdict::SEVERITY_HIGH) {
            return Suppressor::SEV_HARD;
        }
        if ($action === Decision::BLOCK || $action === Decision::DECEIVE) {
            return Suppressor::SEV_MEDIUM;
        }

        return Suppressor::SEV_SOFT;
    }

    /** The stable per-actor seed sha1(actorId + siteSalt) (§2.8). */
    public function seedFor(RequestEvidence $e)
    {
        return sha1($e->actorId() . '|' . $this->siteSalt);
    }

    /** A minimal opaque Verdict for the cheap-static / pin-replay paths (no classify() was run). */
    private function probeVerdict(RequestEvidence $e, $p)
    {
        $onRealRoute = ($p instanceof SiteProfile) ? $p->routeExists($e->path()) : false;

        return new Verdict(Verdict::SCANNER_PROBE, false, 'probe', 0, Verdict::SEVERITY_LOW, $onRealRoute);
    }

    // -----------------------------------------------------------------------------------------------
    // helpers
    // -----------------------------------------------------------------------------------------------

    private function protectMode($position)
    {
        $posture = $this->config->posture();

        return $position === PolicyConfig::POSITION_BEFORE
            && ($posture === PolicyConfig::POSTURE_WAF || $posture === PolicyConfig::POSTURE_BOTH);
    }

    /** Honeypot at the before-position observes only (acts at the fallback); everyone else may deceive. */
    private function allowEarnedDeceive($position)
    {
        return !($this->config->posture() === PolicyConfig::POSTURE_HONEYPOT && $position === PolicyConfig::POSITION_BEFORE);
    }

    private function rankOf($action)
    {
        return isset(self::$rank[$action]) ? self::$rank[$action] : 0;
    }

    private function isScannerUa(RequestEvidence $e)
    {
        $ua = strtolower((string) $e->header('user-agent'));
        if ($ua === '') {
            return false;
        }
        foreach (self::$scannerUas as $tok) {
            if (strpos($ua, $tok) !== false) {
                return true;
            }
        }

        return false;
    }

    private function isExemptUa(RequestEvidence $e, array $exempt)
    {
        $ua = (string) $e->header('user-agent');
        foreach ($exempt as $x) {
            if ($x !== '' && strpos($ua, (string) $x) !== false) {
                return true;
            }
        }

        return false;
    }

    /** Match a path against a set of exact paths or '*'-globs (e.g. '*.map'). */
    private function pathMatches($path, array $patterns)
    {
        foreach ($patterns as $pat) {
            $pat = (string) $pat;
            if ($pat === $path) {
                return true;
            }
            if (strpos($pat, '*') !== false) {
                $re = '#^' . str_replace('\\*', '.*', preg_quote($pat, '#')) . '$#';
                if (preg_match($re, $path)) {
                    return true;
                }
            }
        }

        return false;
    }

    private function bandReason($band)
    {
        if ($band === Verdict::SCANNER_PROBE) {
            return 'scanner-probe';
        }
        if ($band === Verdict::ATTACK_CLASS) {
            return 'attack-class';
        }
        if ($band === Verdict::SUSPICIOUS) {
            return 'suspicious';
        }

        return 'allow';
    }

    private function capReason($ceiling, $reason)
    {
        if ($ceiling === Decision::LOG) {
            return $reason === 'allow' ? 'log' : $reason;
        }

        return $reason;
    }
}
