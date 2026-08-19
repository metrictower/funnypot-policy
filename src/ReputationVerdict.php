<?php

namespace Funnypot\Policy;

/**
 * F's verdict enum + a bounded score + a source marking (design §2.2). A fail-open/inert result carries
 * verdict='unknown', score=null, source='fail-open' — so a caller can never mistake "could not check"
 * (unknown) for "data exists, looks fine" (clean). Reputation is a modifier, never primary, and never
 * sufficient to deceive (§4) — this VO only reports; the precedence decides what it means.
 *
 * `usageType` surfaces F's H1 context.usage_type (e.g. 'datacenter') for the S3 "bot-UA + datacenter IP"
 * fusion. Untyped props + docblocks (typed properties are 7.4+).
 */
final class ReputationVerdict
{
    const VERDICT_UNKNOWN    = 'unknown';
    const VERDICT_CLEAN      = 'clean';
    const VERDICT_SUSPICIOUS = 'suspicious';
    const VERDICT_MALICIOUS  = 'malicious';
    const VERDICT_CRITICAL   = 'critical';

    const SOURCE_MIRROR    = 'mirror';    // the synced local blacklist mirror (O1)
    const SOURCE_CACHE     = 'cache';     // F's per-IP verdict cache
    const SOURCE_FAIL_OPEN = 'fail-open'; // inert / down / breaker — no verdict
    const SOURCE_ABSENT    = 'absent';    // nothing covers the IP

    /** @var string one of the VERDICT_* constants */
    private $verdict;
    /** @var int|null 0-100 bounded score; null when unknown */
    private $score;
    /** @var string one of the SOURCE_* constants */
    private $source;
    /** @var string|null F's context.usage_type, e.g. 'datacenter' (the S3 fusion input) */
    private $usageType;

    /**
     * @param string      $verdict
     * @param int|null    $score
     * @param string      $source
     * @param string|null $usageType
     */
    public function __construct($verdict, $score, $source, $usageType = null)
    {
        $this->verdict = (string) $verdict;
        $this->score = $score === null ? null : (int) $score;
        $this->source = (string) $source;
        $this->usageType = $usageType === null ? null : (string) $usageType;
    }

    /** The uniform fail-open/inert result: unknown verdict, null score. */
    public static function failOpen()
    {
        return new self(self::VERDICT_UNKNOWN, null, self::SOURCE_FAIL_OPEN, null);
    }

    /** Nothing in the mirror/cache covers this IP. */
    public static function absent()
    {
        return new self(self::VERDICT_UNKNOWN, null, self::SOURCE_ABSENT, null);
    }

    public function verdict()
    {
        return $this->verdict;
    }

    public function score()
    {
        return $this->score;
    }

    public function source()
    {
        return $this->source;
    }

    public function usageType()
    {
        return $this->usageType;
    }

    /** verdict is malicious or critical (the block_verdicts default). */
    public function isMalicious()
    {
        return $this->verdict === self::VERDICT_MALICIOUS || $this->verdict === self::VERDICT_CRITICAL;
    }

    /** verdict is suspicious. */
    public function isSuspicious()
    {
        return $this->verdict === self::VERDICT_SUSPICIOUS;
    }

    /** No usable verdict (unknown). */
    public function isUnknown()
    {
        return $this->verdict === self::VERDICT_UNKNOWN;
    }
}
