<?php

namespace Funnypot\Policy\Report;

use Funnypot\Policy\BotSignals;
use Funnypot\Policy\Net;
use Funnypot\Policy\Port\Clock;
use Funnypot\Policy\Port\Logger;
use Funnypot\Policy\Port\StateStoreInterface;
use Funnypot\Policy\PolicyConfig;
use Funnypot\Policy\ReportIntent;

/**
 * Report suppression + scoring (design §9) — the production-validated iCabbiTools 4-layer model:
 * 24h verdict-dedup, per-IP alert cap, buffer-and-collapse, and a score-gate fed by a read-time-decay
 * accumulator; plus the >=2-source/>=200/90d aggregate-ban rule and the allowlist/self/safe/OAST
 * backstops re-checked at EVERY mutating point. Pure decision logic over the injected StateStore.
 */
final class Suppressor
{
    const SEV_SOFT   = 'soft';
    const SEV_MEDIUM = 'medium';
    const SEV_HARD   = 'hard'; // a hard tell (unambiguous exploit) — effectively instant, bypasses the gate

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
     * Decide whether to emit a ReportIntent for an event, applying the backstops + the 4 suppression
     * layers. Returns the intent to enqueue, or null when suppressed.
     *
     * @param string $ip
     * @param string $result   a non-sensitive result label ('deceive','block','log',...)
     * @param string $source   the reporting source id
     * @param string $severity SEV_SOFT | SEV_MEDIUM | SEV_HARD
     * @param array  $ctx      optional {path, asn, botSignals: BotSignals|null, anomaly: int}
     * @return ReportIntent|null
     */
    public function consider($ip, $result, $source, $severity, array $ctx = array())
    {
        $asn = isset($ctx['asn']) ? $ctx['asn'] : null;
        $path = isset($ctx['path']) ? (string) $ctx['path'] : '';

        // --- BACKSTOPS FIRST (allowlist-everywhere / self / safe-path). An allowlisted actor is never
        //     scored or reported even if a downstream layer would have (defense in depth). ---
        if ($this->isBackstopped($ip, $asn, $path)) {
            return null;
        }

        $sup = $this->config->suppression();
        $scoreKey = Net::normaliseV6($ip);

        // --- Layer 4 (score gate) fed by the read-time-decay accumulator. A hard tell bypasses the gate
        //     (an unambiguous exploit alerts instantly); soft/medium accumulate toward it. ---
        $inc = $this->increment($severity);
        $hardTell = ($severity === self::SEV_HARD);
        $score = $this->store->decayScore($scoreKey, $inc, $sup['decay']['base_ttl_s'], $sup['decay']['cap_ttl_s']);
        if (!$hardTell && $score < $sup['score_gate']) {
            return null; // recorded (the accumulator advanced), but not alerted
        }

        // --- Layer 1 (24h verdict-dedup): the identical verdict about the identical actor from the
        //     identical source is reported once per window. ---
        $dedupKey = sha1($ip . '|' . $result . '|' . $source);
        if ($this->store->seenVerdict($dedupKey, $sup['verdict_dedup_hours'] * 3600)) {
            return null;
        }

        // --- Layer 2 (per-IP alert cap): a noisy single actor cannot flood the channel. ---
        if ($this->store->incrAlertCount($ip, $sup['per_ip_cap_window_s']) > $sup['per_ip_alert_cap']) {
            return null;
        }

        return $this->buildIntent($scoreKey, $result, $source, $score, $dedupKey, $hardTell, $ctx);
    }

    /**
     * Layer 3 (buffer-and-collapse): buffer an alert into a group so a burst collapses into one message.
     * Returns the collapsed count so far.
     */
    public function buffer($groupKey, ReportIntent $intent)
    {
        $sup = $this->config->suppression();

        return $this->store->bufferReport($groupKey, array(
            'ip' => $intent->ip(),
            'result' => $intent->resultLabel(),
            'source' => $intent->source(),
            'score' => $intent->score(),
        ), $sup['buffer_ttl_s']);
    }

    /**
     * Drain the buffered groups into one collapsed ReportIntent per group, carrying the (xN) repeat count
     * in the result label.
     *
     * @return ReportIntent[]
     */
    public function drain()
    {
        $out = array();
        foreach ($this->store->takeReportBuffer() as $groupKey => $reports) {
            $n = count($reports);
            if ($n === 0) {
                continue;
            }
            $first = $reports[0];
            $label = $first['result'] . ' (x' . $n . ')';
            $out[] = new ReportIntent($first['ip'], $label, $first['source'], $first['score'], array(), sha1((string) $groupKey), null, null, false);
        }

        return $out;
    }

    /**
     * The aggregate-ban rule: escalate to a ban recommendation only with >=2 DISTINCT sources AND
     * total_score >= 200 over a 90-day window (mirrors the mainnet >=2-source listing gate — a lone
     * source can never manufacture a ban).
     */
    public function aggregateBan($scoreKey)
    {
        $sup = $this->config->suppression();
        $agg = $this->store->aggregateScore(Net::normaliseV6($scoreKey), $sup['aggregate']['window_days']);

        return $agg->distinctSourceCount() >= $sup['aggregate']['min_sources']
            && $agg->total() >= $sup['aggregate']['min_total_score'];
    }

    // -----------------------------------------------------------------------------------------------
    // internals
    // -----------------------------------------------------------------------------------------------

    private function buildIntent($scoreKey, $result, $source, $score, $dedupKey, $hardTell, array $ctx)
    {
        $categories = array();
        $confidence = null;
        $signals = null;

        $bot = isset($ctx['botSignals']) && $ctx['botSignals'] instanceof BotSignals ? $ctx['botSignals'] : null;
        $anomaly = isset($ctx['anomaly']) ? (int) $ctx['anomaly'] : 0;

        if ($bot !== null && $bot->isBotShaped()) {
            $categories[] = ReportIntent::CATEGORY_BAD_BOT;
            $confidence = $this->botConfidence($bot); // signal-weighted (S4)
            // The opt-in, fingerprint-safe signals object rides the report ONLY when telemetry is on (T4).
            if ($this->config->botSignals()['telemetry']) {
                $signals = ReportIntent::signalsObject($bot, $anomaly);
            }
        }

        return new ReportIntent($scoreKey, $result, $source, (int) $score, $categories, $dedupKey, $confidence, $signals, $hardTell);
    }

    /** Signal-weighted confidence for the bad-bot class, bounded to [0,1] (S4). */
    private function botConfidence(BotSignals $bot)
    {
        $c = $bot->weakSignalCount() * 0.2;
        if ($bot->isScannerUa()) {
            $c += 0.6;
        }
        if ($c > 1.0) {
            $c = 1.0;
        }

        return $c;
    }

    private function increment($severity)
    {
        $decay = $this->config->suppression()['decay'];
        if ($severity === self::SEV_HARD) {
            return $decay['inc_hard'];
        }
        if ($severity === self::SEV_MEDIUM) {
            return $decay['inc_medium'];
        }

        return $decay['inc_soft'];
    }

    /** The allowlist-everywhere / self / safe-path backstop, matched by containment (P2/Q2/Q4). */
    public function isBackstopped($ip, $asn, $path)
    {
        if (in_array($ip, $this->config->selfIps(), true)) {
            return true;
        }
        $al = $this->config->allowlist();
        if (in_array($ip, $al['ips'], true)) {
            return true;
        }
        foreach ($al['cidrs'] as $cidr) {
            if (Net::contains($cidr, $ip)) {
                return true;
            }
        }
        if ($asn !== null && $asn !== '') {
            foreach ($al['asns'] as $a) {
                if (strcasecmp((string) $a, (string) $asn) === 0) {
                    return true;
                }
            }
        }
        if ($path !== '' && in_array($path, $al['safe_paths'], true)) {
            return true;
        }

        return false;
    }

    /**
     * OAST hygiene (§9): attacker payloads embed OAST/callback URL-shaped paths. This returns a REDACTED
     * shape — the live attacker-controlled URL is NEVER forwarded verbatim into any log/report/DNS sink,
     * so the honeypot cannot be turned into an SSRF/beacon amplifier.
     */
    public function redactOast($path)
    {
        $path = (string) $path;
        if (strpos($path, '://') !== false || strpos($path, '//') === 0 || preg_match('#[a-z0-9-]+\.[a-z]{2,}#i', $path)) {
            return '[redacted-url]';
        }

        return $path;
    }
}
