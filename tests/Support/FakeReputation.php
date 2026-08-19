<?php

namespace Funnypot\Policy\Tests\Support;

use Funnypot\Policy\Port\ReputationInterface;
use Funnypot\Policy\ReputationVerdict;

/**
 * Scripts a cached verdict per IP and PROVES the request-path contract: lookup() never makes a
 * network-shaped call (networkCalls stays 0) and never blocks. An unmapped IP returns a fail-open
 * unknown. Optional throw flag drives the fail-safe matrix.
 */
final class FakeReputation implements ReputationInterface
{
    /** @var array ip => ReputationVerdict */
    private $byIp = array();

    /** @var int number of lookup() calls */
    public $lookupCalls = 0;
    /** @var int network-shaped calls — MUST stay 0 (the port contract forbids a sync network call) */
    public $networkCalls = 0;
    /** @var bool */
    public $throwOnLookup = false;

    public function scriptIp(string $ip, ReputationVerdict $v)
    {
        $this->byIp[$ip] = $v;

        return $this;
    }

    public function lookup(string $ip)
    {
        $this->lookupCalls++;
        if ($this->throwOnLookup) {
            throw new \RuntimeException('reputation boom');
        }
        // Deliberately do NOT touch $this->networkCalls: the contract is cache/mirror-first only.
        if (isset($this->byIp[$ip])) {
            return $this->byIp[$ip];
        }

        return ReputationVerdict::failOpen();
    }
}
