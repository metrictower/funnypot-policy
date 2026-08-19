<?php

namespace Funnypot\Policy;

/**
 * All policy configuration + defaults (design §8), built via fromArray() because 7.3 has no named args.
 * The array is plain serializable data — a WordPress admin screen and a Laravel config file are two
 * front-ends that emit the IDENTICAL structure. Choosing honeypot vs WAF and before vs fallback is
 * picking values here, never a code change (M4). Untyped props + docblocks (typed properties are 7.4+).
 */
final class PolicyConfig
{
    const POSTURE_HONEYPOT = 'honeypot';
    const POSTURE_WAF      = 'WAF';
    const POSTURE_BOTH     = 'both';

    const POSITION_BEFORE   = 'before';
    const POSITION_FALLBACK = 'fallback';

    /** @var string honeypot | WAF | both */
    private $posture;
    /** @var array ['fallback'=>bool, 'before'=>bool] */
    private $position;
    /** @var array Verdict-classification => action */
    private $actions;
    /** @var array reputation block */
    private $reputation;
    /** @var array learn-then-enforce */
    private $learn;
    /** @var array country gate (decision R) */
    private $country;
    /** @var array bot-signals (decision S/T) */
    private $botSignals;
    /** @var array pin */
    private $pin;
    /** @var array suppression (§9) */
    private $suppression;
    /** @var array allowlist (ips/cidrs/asns/safe_paths) */
    private $allowlist;
    /** @var array operator's own egress IPs */
    private $selfIps;

    private function __construct()
    {
    }

    /**
     * @param array $opts nested assoc array (design §8)
     * @return self
     */
    public static function fromArray(array $opts)
    {
        $c = new self();

        $c->posture = isset($opts['posture']) ? (string) $opts['posture'] : self::POSTURE_HONEYPOT;
        $preset = self::presetPosition($c->posture);

        // Position: preset seeds it; an explicit 'position' key overrides per field (M4 knobs).
        $pos = $preset;
        if (isset($opts['position']) && is_array($opts['position'])) {
            if (array_key_exists('fallback', $opts['position'])) {
                $pos['fallback'] = (bool) $opts['position']['fallback'];
            }
            if (array_key_exists('before', $opts['position'])) {
                $pos['before'] = (bool) $opts['position']['before'];
            }
        }
        $c->position = $pos;

        // Per-band action ceiling on REAL routes (§5). Config keys use underscores; internal keys use the
        // Verdict classification constants so actionFor() can look up a Verdict directly.
        $a = isset($opts['actions']) && is_array($opts['actions']) ? $opts['actions'] : array();
        $c->actions = array(
            Verdict::CLEAN         => isset($a['clean']) ? (string) $a['clean'] : Decision::ALLOW,
            Verdict::SUSPICIOUS    => isset($a['suspicious']) ? (string) $a['suspicious'] : Decision::LOG,
            Verdict::ATTACK_CLASS  => isset($a['attack_class']) ? (string) $a['attack_class'] : Decision::BLOCK,
            Verdict::SCANNER_PROBE => isset($a['scanner_probe']) ? (string) $a['scanner_probe'] : Decision::DECEIVE,
        );

        $r = isset($opts['reputation']) && is_array($opts['reputation']) ? $opts['reputation'] : array();
        $c->reputation = array(
            'enabled' => isset($r['enabled']) ? (bool) $r['enabled'] : false,
            'block_verdicts' => isset($r['block_verdicts']) && is_array($r['block_verdicts'])
                ? array_values($r['block_verdicts'])
                : array(ReputationVerdict::VERDICT_MALICIOUS, ReputationVerdict::VERDICT_CRITICAL),
            'min_block_score' => array_key_exists('min_block_score', $r) && $r['min_block_score'] !== null
                ? (int) $r['min_block_score'] : null,
            // as_primary is HARD false — reputation can never be primary (§4). A truthy value is ignored.
            'as_primary' => false,
        );

        $l = isset($opts['learn']) && is_array($opts['learn']) ? $opts['learn'] : array();
        $c->learn = array(
            'shadow_days' => isset($l['shadow_days']) ? (int) $l['shadow_days'] : 7,
            'shadow_min_reqs' => isset($l['shadow_min_reqs']) ? (int) $l['shadow_min_reqs'] : 5000,
            'baseline_excluded' => isset($l['baseline_excluded']) && is_array($l['baseline_excluded'])
                ? array_values($l['baseline_excluded']) : array(),
            'kill_switch' => isset($l['kill_switch']) ? (bool) $l['kill_switch'] : false,
        );

        $co = isset($opts['country']) && is_array($opts['country']) ? $opts['country'] : array();
        $c->country = array(
            'enabled' => isset($co['enabled']) ? (bool) $co['enabled'] : false,
            'mode' => isset($co['mode']) ? (string) $co['mode'] : 'deny',
            'countries' => isset($co['countries']) && is_array($co['countries'])
                ? array_map('strtoupper', array_map('strval', array_values($co['countries']))) : array(),
            'action' => isset($co['action']) ? (string) $co['action'] : 'modifier',
        );

        $b = isset($opts['bot_signals']) && is_array($opts['bot_signals']) ? $opts['bot_signals'] : array();
        $c->botSignals = array(
            'enabled' => isset($b['enabled']) ? (bool) $b['enabled'] : true,
            'exempt_uas' => isset($b['exempt_uas']) && is_array($b['exempt_uas']) ? array_values($b['exempt_uas']) : array(),
            'exempt_paths' => isset($b['exempt_paths']) && is_array($b['exempt_paths']) ? array_values($b['exempt_paths']) : array(),
            'telemetry' => isset($b['telemetry']) ? (bool) $b['telemetry'] : false,
        );

        $pn = isset($opts['pin']) && is_array($opts['pin']) ? $opts['pin'] : array();
        $c->pin = array(
            'ttl_seconds' => isset($pn['ttl_seconds']) ? (int) $pn['ttl_seconds'] : 3600,
        );

        $c->suppression = self::suppressionFrom(isset($opts['suppression']) && is_array($opts['suppression']) ? $opts['suppression'] : array());

        $al = isset($opts['allowlist']) && is_array($opts['allowlist']) ? $opts['allowlist'] : array();
        $c->allowlist = array(
            'ips' => isset($al['ips']) && is_array($al['ips']) ? array_values($al['ips']) : array(),
            'cidrs' => isset($al['cidrs']) && is_array($al['cidrs']) ? array_values($al['cidrs']) : array(),
            'asns' => isset($al['asns']) && is_array($al['asns']) ? array_values($al['asns']) : array(),
            'safe_paths' => isset($al['safe_paths']) && is_array($al['safe_paths']) ? array_values($al['safe_paths']) : array(),
        );

        $c->selfIps = isset($opts['self_ips']) && is_array($opts['self_ips']) ? array_values($opts['self_ips']) : array();

        return $c;
    }

    private static function presetPosition($posture)
    {
        if ($posture === self::POSTURE_WAF) {
            return array('fallback' => false, 'before' => true);
        }
        if ($posture === self::POSTURE_BOTH) {
            return array('fallback' => true, 'before' => true);
        }

        return array('fallback' => true, 'before' => false); // honeypot default
    }

    private static function suppressionFrom(array $s)
    {
        $agg = isset($s['aggregate']) && is_array($s['aggregate']) ? $s['aggregate'] : array();
        $decay = isset($s['decay']) && is_array($s['decay']) ? $s['decay'] : array();

        return array(
            'verdict_dedup_hours' => isset($s['verdict_dedup_hours']) ? (int) $s['verdict_dedup_hours'] : 24,
            'per_ip_alert_cap' => isset($s['per_ip_alert_cap']) ? (int) $s['per_ip_alert_cap'] : 100,
            'per_ip_cap_window_s' => isset($s['per_ip_cap_window_s']) ? (int) $s['per_ip_cap_window_s'] : 600,
            'buffer_ttl_s' => isset($s['buffer_ttl_s']) ? (int) $s['buffer_ttl_s'] : 900,
            'score_gate' => isset($s['score_gate']) ? (int) $s['score_gate'] : 200,
            'aggregate' => array(
                'min_sources' => isset($agg['min_sources']) ? (int) $agg['min_sources'] : 2,
                'min_total_score' => isset($agg['min_total_score']) ? (int) $agg['min_total_score'] : 200,
                'window_days' => isset($agg['window_days']) ? (int) $agg['window_days'] : 90,
            ),
            'decay' => array(
                'base_ttl_s' => isset($decay['base_ttl_s']) ? (int) $decay['base_ttl_s'] : 600,
                'cap_ttl_s' => isset($decay['cap_ttl_s']) ? (int) $decay['cap_ttl_s'] : 86400,
                'inc_soft' => isset($decay['inc_soft']) ? (int) $decay['inc_soft'] : 1,
                'inc_medium' => isset($decay['inc_medium']) ? (int) $decay['inc_medium'] : 10,
                'inc_hard' => isset($decay['inc_hard']) ? (int) $decay['inc_hard'] : 100,
            ),
        );
    }

    // --- getters ---

    public function posture()
    {
        return $this->posture;
    }

    public function position()
    {
        return $this->position;
    }

    public function positionEnabled($which)
    {
        return isset($this->position[$which]) && $this->position[$which] === true;
    }

    /** The action configured for a Verdict classification band. */
    public function actionFor($classification)
    {
        return isset($this->actions[$classification]) ? $this->actions[$classification] : Decision::ALLOW;
    }

    /**
     * The real-route action ceiling for a position under the current posture (design §8 table). Fallback
     * is always FP-free-by-construction, so its ceiling is deceive; the before ceiling depends on posture.
     */
    public function ceiling($position)
    {
        if ($position === self::POSITION_FALLBACK) {
            return Decision::DECEIVE;
        }
        // before position:
        if ($this->posture === self::POSTURE_WAF || $this->posture === self::POSTURE_BOTH) {
            return Decision::BLOCK;
        }

        return Decision::LOG; // honeypot observes before
    }

    public function reputation()
    {
        return $this->reputation;
    }

    public function learn()
    {
        return $this->learn;
    }

    public function country()
    {
        return $this->country;
    }

    public function botSignals()
    {
        return $this->botSignals;
    }

    public function pin()
    {
        return $this->pin;
    }

    public function suppression()
    {
        return $this->suppression;
    }

    public function allowlist()
    {
        return $this->allowlist;
    }

    public function selfIps()
    {
        return $this->selfIps;
    }
}
