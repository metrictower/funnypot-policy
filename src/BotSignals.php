<?php

namespace Funnypot\Policy;

/**
 * The S request-shape bot-signal set (design §2.1, decision S1), computed in core's classify() and
 * carried on the Verdict. INPUT-SIDE ONLY — the flags/classes/token are never emitted, so they are
 * fingerprint-safe (§10). Deliberately NOT an outdated-UA/version-age check: the set is header PRESENCE
 * + SELF-CONSISTENCY + the digit-stripped structural fingerprint, tolerant of old-but-legit clients.
 *
 * The composite decision on these signals is the policy engine's job (§4), never core's; a single weak
 * signal never decides (S2). Untyped props + docblocks (typed properties are 7.4+).
 */
final class BotSignals
{
    // UA class (S1). Scanner is an unambiguous tool signature (decisive); script is a modifier; empty is
    // a weak signal; browser/unknown carry no UA-class weight on their own.
    const UA_BROWSER = 'browser';
    const UA_UNKNOWN = 'unknown';
    const UA_EMPTY   = 'empty';
    const UA_SCRIPT  = 'script';
    const UA_SCANNER = 'scanner';

    /** @var string one of the UA_* constants */
    private $uaClass;
    /** @var array opaque presence/self-consistency flag tokens (e.g. 'missing_accept_language') */
    private $flags;
    /** @var string the digit-stripped, sorted-list structural fingerprint token (the JA4-H idea) */
    private $fingerprint;

    /**
     * @param string $uaClass
     * @param array  $flags       opaque flag tokens — never a signature string
     * @param string $fingerprint opaque structural token
     */
    public function __construct($uaClass = self::UA_UNKNOWN, array $flags = array(), $fingerprint = '')
    {
        $this->uaClass = (string) $uaClass;
        $this->flags = array_values($flags);
        $this->fingerprint = (string) $fingerprint;
    }

    /** The empty (no signals) set — a well-formed browser request contributes nothing. */
    public static function none()
    {
        return new self(self::UA_BROWSER, array(), '');
    }

    public function uaClass()
    {
        return $this->uaClass;
    }

    public function flags()
    {
        return $this->flags;
    }

    public function fingerprint()
    {
        return $this->fingerprint;
    }

    /** A scanner UA is an unambiguous tool signature — decisive on its own (S2). */
    public function isScannerUa()
    {
        return $this->uaClass === self::UA_SCANNER;
    }

    /**
     * Count of WEAK signals present (an empty UA, a script UA, plus each presence/self-consistency
     * flag). Each is a modifier that accumulates — never decisive alone (S2). The policy fuses this into
     * the composite scrutiny (§4); it is not itself a gate.
     *
     * @return int
     */
    public function weakSignalCount()
    {
        $n = count($this->flags);
        if ($this->uaClass === self::UA_EMPTY || $this->uaClass === self::UA_SCRIPT) {
            $n++;
        }

        return $n;
    }

    /** Any signal at all present (used for the report bad-bot category / fingerprint-safe telemetry). */
    public function isBotShaped()
    {
        return $this->isScannerUa() || $this->weakSignalCount() > 0;
    }
}
