<?php

namespace Funnypot\Policy;

/**
 * A deception-consistency pin (design §2.3, M5). A deceived actor is pinned so every subsequent request
 * replays the SAME action with the SAME seed → the fakes stay mutually coherent (the anti-unmask
 * property). Untyped props + docblocks (typed properties are 7.4+).
 */
final class Pin
{
    /** @var string the pinned Decision action */
    private $action;
    /** @var string the deterministic actor seed to re-use */
    private $seed;
    /** @var int epoch seconds when this pin expires */
    private $expiresAt;

    public function __construct(string $action, string $seed, int $expiresAt)
    {
        $this->action = $action;
        $this->seed = $seed;
        $this->expiresAt = $expiresAt;
    }

    public function action()
    {
        return $this->action;
    }

    public function seed()
    {
        return $this->seed;
    }

    public function expiresAt()
    {
        return $this->expiresAt;
    }
}
