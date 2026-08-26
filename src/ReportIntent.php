<?php

namespace Funnypot\Policy;

/**
 * A suppression-shaped, opaque-handle report the adapter MAY enqueue (design §9). Side-effect-free — a
 * Decision merely carries it; the adapter decides whether to enqueue (to mainnet via F's reporter,
 * and/or an operator alert channel).
 *
 * Carries NO raw payload and NO signature string. `categories` are opaque tokens (the S4 'bad_bot' class
 * included when the actor is bot-shaped); the optional `signals` object (decision T) is flags/classes/
 * tokens only, present ONLY when bot_signals.telemetry is enabled (T4/T5). Untyped props + docblocks.
 */
final class ReportIntent
{
    const CATEGORY_BAD_BOT = 'bad_bot';

    /** @var string actor IP (normalised score_key) */
    private $ip;
    /** @var string a non-sensitive result label */
    private $resultLabel;
    /** @var string the reporting source id */
    private $source;
    /** @var int the actor's decayed score at report time */
    private $score;
    /** @var array opaque category tokens */
    private $categories;
    /** @var float|null signal-weighted confidence for the bad-bot class (S4), 0..1 */
    private $confidence;
    /** @var string the 24h dedup key sha1(ip+result+source) */
    private $dedupKey;
    /** @var array|null the opt-in signals object (decision T); null unless telemetry is enabled */
    private $signals;
    /** @var bool this event is an unambiguous exploit (hard tell) — bypasses the score gate (§9) */
    private $hardTell;

    /**
     * @param string     $ip
     * @param string     $resultLabel
     * @param string     $source
     * @param int        $score
     * @param array      $categories opaque tokens only
     * @param string     $dedupKey
     * @param float|null $confidence
     * @param array|null $signals    fingerprint-safe flags/classes/tokens only, or null
     * @param bool       $hardTell
     */
    public function __construct($ip, $resultLabel, $source, $score, array $categories, $dedupKey, $confidence = null, $signals = null, $hardTell = false)
    {
        $this->ip = (string) $ip;
        $this->resultLabel = (string) $resultLabel;
        $this->source = (string) $source;
        $this->score = (int) $score;
        $this->categories = array_values($categories);
        $this->dedupKey = (string) $dedupKey;
        $this->confidence = $confidence === null ? null : (float) $confidence;
        $this->signals = $signals === null ? null : (array) $signals;
        $this->hardTell = (bool) $hardTell;
    }

    /**
     * Build the fingerprint-safe signals object (decision T5): opaque flags/UA-class/fingerprint token +
     * the local anomaly summary. NEVER a raw payload or a signature string (§10).
     *
     * @return array
     */
    public static function signalsObject(BotSignals $bs, int $anomaly)
    {
        return array(
            'ua_class' => $bs->uaClass(),
            'flags' => $bs->flags(),
            'fingerprint' => $bs->fingerprint(),
            'anomaly' => $anomaly,
        );
    }

    public function ip()
    {
        return $this->ip;
    }

    public function resultLabel()
    {
        return $this->resultLabel;
    }

    public function source()
    {
        return $this->source;
    }

    public function score()
    {
        return $this->score;
    }

    public function categories()
    {
        return $this->categories;
    }

    public function hasCategory(string $c)
    {
        return in_array($c, $this->categories, true);
    }

    public function confidence()
    {
        return $this->confidence;
    }

    public function dedupKey()
    {
        return $this->dedupKey;
    }

    public function signals()
    {
        return $this->signals;
    }

    public function isHardTell()
    {
        return $this->hardTell;
    }
}
