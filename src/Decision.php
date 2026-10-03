<?php

namespace Funnypot\Policy;

/**
 * The engine's single output (design §3) — PURE DATA, zero side effects (M3). The adapter reads it and
 * performs the effect. The action enum is closed at four (challenge + tarpit CUT — a PHP-FPM tarpit is a
 * self-DoS; a future `challenge` is an additive constant, not a redesign).
 *
 * Status is APP-CHOSEN, never model-chosen (invariant 5) — no model-driven 3xx, no open redirect.
 * `reason` is constrained to a non-sensitive label (never a raw payload or a signature string, §10).
 * Untyped props + docblocks (typed properties are 7.4+).
 */
final class Decision
{
    const ALLOW   = 'allow';    // pass to the real app, do nothing
    const LOG     = 'log';      // pass to the real app, but record/observe (shadow, or below-block)
    const BLOCK   = 'block';    // the adapter returns an honest refusal (protect-mode only)
    const DECEIVE = 'deceive';  // the adapter emits the fakeHandle from synthesize()

    /**
     * The closed set of non-sensitive reason labels. Constraining reason() to this set is what makes a
     * fingerprint leak (a signature string in a log/decision) impossible by construction (§10).
     *
     * @var array
     */
    private static $reasons = array(
        'allow', 'log', 'block', 'deceive',
        'allowlist', 'self-ip', 'safe-path', 'pin', 'blocklist',
        'sacrificial-path', 'malicious-ua', 'country',
        'reputation-modifier', 'reputation-block', 'bot-signal-composite',
        'shadow', 'fallback-deceive', 'attack-class', 'scanner-probe', 'suspicious', 'ambient',
        'failsafe',
    );

    /** @var string one of the four action constants */
    private $action;
    /** @var int|null app-chosen status */
    private $status;
    /** @var FakeResponse|null present iff action === DECEIVE */
    private $fakeHandle;
    /** @var int|null seconds to pin this actor's treatment (M5) */
    private $pinTtl;
    /** @var ReportIntent|null a suppression-shaped report the adapter may enqueue (§9), or null */
    private $report;
    /** @var string a non-sensitive label for logging */
    private $reason;

    private function __construct($action, $status, $fakeHandle, $pinTtl, $reason)
    {
        $this->action = $action;
        $this->status = $status === null ? null : (int) $status;
        $this->fakeHandle = $fakeHandle;
        $this->pinTtl = $pinTtl === null ? null : (int) $pinTtl;
        $this->report = null;
        $this->reason = self::safeReason($reason);
    }

    /** Reject anything that is not one of the closed non-sensitive labels (fingerprint-safety, §10). */
    private static function safeReason($reason)
    {
        $r = (string) $reason;
        if (!in_array($r, self::$reasons, true)) {
            throw new \InvalidArgumentException('Decision reason must be a non-sensitive label');
        }

        return $r;
    }

    // --- factories ---

    public static function allow($reason = 'allow')
    {
        return new self(self::ALLOW, null, null, null, $reason);
    }

    public static function log($reason = 'log')
    {
        return new self(self::LOG, null, null, null, $reason);
    }

    public static function block(int $status = 403, $reason = 'block')
    {
        return new self(self::BLOCK, $status, null, null, $reason);
    }

    public static function deceive(FakeResponse $fake, $pinTtl = null, $reason = 'deceive')
    {
        $status = $fake->status();

        return new self(self::DECEIVE, $status, $fake, $pinTtl, $reason);
    }

    /** Attach a report intent (returns a new Decision; the original is unchanged — still side-effect-free). */
    public function withReport(ReportIntent $report)
    {
        $clone = clone $this;
        $clone->report = $report;

        return $clone;
    }

    /** Re-label the reason (validated against the closed set). */
    public function withReason($reason)
    {
        $clone = clone $this;
        $clone->reason = self::safeReason($reason);

        return $clone;
    }

    // --- getters ---

    public function action()
    {
        return $this->action;
    }

    public function status()
    {
        return $this->status;
    }

    public function fakeHandle()
    {
        return $this->fakeHandle;
    }

    public function pinTtl()
    {
        return $this->pinTtl;
    }

    public function report()
    {
        return $this->report;
    }

    public function reason()
    {
        return $this->reason;
    }

    public function isAllow()
    {
        return $this->action === self::ALLOW;
    }

    public function isDeceive()
    {
        return $this->action === self::DECEIVE;
    }
}
