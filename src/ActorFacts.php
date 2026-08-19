<?php

namespace Funnypot\Policy;

/**
 * Rolling per-actor facts for the TUNING FP heuristic (design §6). "Otherwise-legit actor" =
 * authSession AND cleanReputation AND loadsAssets AND no other rule matches in 30 days. Untyped props +
 * docblocks (typed properties are 7.4+).
 */
final class ActorFacts
{
    /** @var bool the actor has an authenticated session */
    private $authSession;
    /** @var bool the actor loads page assets (a real browser, not a bare probe) */
    private $loadsAssets;
    /** @var int other rule matches attributed to this actor in the last 30 days */
    private $matches30d;
    /** @var int epoch seconds the actor was first seen */
    private $firstSeen;

    public function __construct($authSession = false, $loadsAssets = false, $matches30d = 0, $firstSeen = 0)
    {
        $this->authSession = (bool) $authSession;
        $this->loadsAssets = (bool) $loadsAssets;
        $this->matches30d = (int) $matches30d;
        $this->firstSeen = (int) $firstSeen;
    }

    public function authSession()
    {
        return $this->authSession;
    }

    public function loadsAssets()
    {
        return $this->loadsAssets;
    }

    public function matches30d()
    {
        return $this->matches30d;
    }

    public function firstSeen()
    {
        return $this->firstSeen;
    }
}
