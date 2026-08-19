<?php

namespace Funnypot\Policy\Tests\Engine;

use Funnypot\Policy\Decision;
use Funnypot\Policy\ReputationVerdict;
use Funnypot\Policy\Verdict;

/**
 * The three reputation rules as table-tested invariants (design §4) — the single most important
 * FP-safety property. Reputation is a mirror-first, cache-first MODIFIER, never primary.
 */
final class ReputationRulesTest extends EngineTestCase
{
    private function malicious($source = ReputationVerdict::SOURCE_MIRROR, $usageType = null)
    {
        return new ReputationVerdict(ReputationVerdict::VERDICT_MALICIOUS, 90, $source, $usageType);
    }

    public function test_allowlist_beats_malicious_reputation()
    {
        $eng = $this->engine(array('allowlist' => array('ips' => array('203.0.113.7'))));
        $this->store->seedMirror('203.0.113.7', ReputationVerdict::VERDICT_MALICIOUS);
        $d = $eng->evaluate($this->request('/x', '203.0.113.7'), $this->profile('wordpress', array('/x')));
        $this->assertSame(Decision::ALLOW, $d->action());
        $this->assertSame('allowlist', $d->reason());
        $this->assertSame(0, $this->ev->classifyCalls); // allowlist short-circuits before classify
    }

    public function test_never_deceive_on_reputation_alone()
    {
        // A malicious IP on a real, existing route with a clean content verdict (no request signal).
        $this->ev->scriptDefault($this->verdict(Verdict::CLEAN, false, '', 0, Verdict::SEVERITY_LOW, true));
        foreach (array('honeypot', 'WAF', 'both') as $posture) {
            $this->store->seedMirror('203.0.113.7', ReputationVerdict::VERDICT_MALICIOUS);
            $eng = $this->engine(array('posture' => $posture, 'reputation' => array('enabled' => true)));
            $d = $eng->evaluate($this->request('/login', '203.0.113.7'), $this->profile('wordpress', array('/login')));
            $this->assertNotSame(Decision::DECEIVE, $d->action(), "posture=$posture must not deceive on reputation alone");
        }
    }

    public function test_lone_malicious_on_innocuous_is_log_by_default()
    {
        // Default posture (honeypot), reputation checking OFF — but the mirror is always consulted (O1).
        $this->ev->scriptDefault($this->verdict(Verdict::CLEAN, false, '', 0, Verdict::SEVERITY_LOW, true));
        $this->store->seedMirror('203.0.113.7', ReputationVerdict::VERDICT_MALICIOUS);
        $eng = $this->engine();
        $d = $eng->evaluate($this->request('/login', '203.0.113.7'), $this->profile('wordpress', array('/login')));
        $this->assertSame(Decision::LOG, $d->action());          // observed, not blocked
        $this->assertSame('reputation-modifier', $d->reason());
    }

    public function test_reputation_block_only_when_opted_in_and_before()
    {
        // A content-suspicious request from a malicious IP.
        $this->ev->scriptDefault($this->verdict(Verdict::SUSPICIOUS, false, '', 30, Verdict::SEVERITY_MEDIUM, true));
        $this->store->seedMirror('203.0.113.7', ReputationVerdict::VERDICT_MALICIOUS);

        // enabled + BEFORE (WAF) -> block.
        $eng = $this->engine(array('posture' => 'WAF', 'reputation' => array('enabled' => true)));
        $this->assertSame(Decision::BLOCK, $eng->evaluate($this->request('/login', '203.0.113.7'), $this->profile('wordpress', array('/login')))->action());

        // enabled + FALLBACK (honeypot) -> not block (protect-mode only blocks at BEFORE).
        $eng2 = $this->engine(array('posture' => 'honeypot', 'reputation' => array('enabled' => true)));
        $this->assertNotSame(Decision::BLOCK, $eng2->evaluate($this->request('/login', '203.0.113.7'), $this->profile('wordpress', array('/login')))->action());

        // disabled + BEFORE -> not block (block-on-reputation is opt-in).
        $eng3 = $this->engine(array('posture' => 'WAF', 'reputation' => array('enabled' => false)));
        $this->assertNotSame(Decision::BLOCK, $eng3->evaluate($this->request('/login', '203.0.113.7'), $this->profile('wordpress', array('/login')))->action());
    }

    public function test_reputation_promotes_only_already_suspicious()
    {
        $this->store->seedMirror('203.0.113.7', ReputationVerdict::VERDICT_MALICIOUS);
        $cfg = array('posture' => 'WAF', 'reputation' => array('enabled' => true));

        // suspicious content + malicious -> promoted to block (rule 1).
        $this->ev->scriptDefault($this->verdict(Verdict::SUSPICIOUS, false, '', 30, Verdict::SEVERITY_MEDIUM, true));
        $this->assertSame(Decision::BLOCK, $this->engine($cfg)->evaluate($this->request('/login', '203.0.113.7'), $this->profile('wordpress', array('/login')))->action());

        // clean content + malicious -> NOT escalated (reputation is not primary).
        $this->ev = new \Funnypot\Policy\Tests\Support\FakeEvaluator();
        $this->ev->scriptDefault($this->verdict(Verdict::CLEAN, false, '', 0, Verdict::SEVERITY_LOW, true));
        $d = $this->engine($cfg)->evaluate($this->request('/login', '203.0.113.7'), $this->profile('wordpress', array('/login')));
        $this->assertNotSame(Decision::BLOCK, $d->action());
        $this->assertNotSame(Decision::DECEIVE, $d->action());
    }

    public function test_lookup_makes_no_network_call()
    {
        $this->store->seedMirror('203.0.113.7', ReputationVerdict::VERDICT_MALICIOUS);
        $eng = $this->engine(array('reputation' => array('enabled' => true)));
        $eng->evaluate($this->request('/login', '203.0.113.7'), $this->profile('wordpress', array('/login')));
        $this->assertSame(0, $this->rep->networkCalls); // never a network-shaped call on the request path
    }

    public function test_mirror_consulted_before_per_ip_lookup()
    {
        $this->ev->scriptDefault($this->verdict(Verdict::CLEAN, false, '', 0, Verdict::SEVERITY_LOW, true));

        // Present in the mirror -> resolved from the mirror; rep.lookup is NEVER called (O1).
        $this->store->seedMirror('203.0.113.7', ReputationVerdict::VERDICT_MALICIOUS);
        $eng = $this->engine(array('reputation' => array('enabled' => true)));
        $eng->evaluate($this->request('/login', '203.0.113.7'), $this->profile('wordpress', array('/login')));
        $this->assertSame(0, $this->rep->lookupCalls);

        // Absent from the mirror -> escalate to the cache-first per-IP lookup.
        $this->rep->scriptIp('198.51.100.9', $this->malicious(ReputationVerdict::SOURCE_CACHE));
        $eng->evaluate($this->request('/login', '198.51.100.9'), $this->profile('wordpress', array('/login')));
        $this->assertSame(1, $this->rep->lookupCalls);
    }

    public function test_mirror_matches_range_by_containment()
    {
        $this->ev->scriptDefault($this->verdict(Verdict::CLEAN, false, '', 0, Verdict::SEVERITY_LOW, true));
        $eng = $this->engine(array('reputation' => array('enabled' => true)));

        // IP inside a seeded /24 resolves from the mirror by containment (a modifier -> log).
        $this->store->seedMirror('203.0.113.0/24', ReputationVerdict::VERDICT_MALICIOUS);
        $d = $eng->evaluate($this->request('/login', '203.0.113.99'), $this->profile('wordpress', array('/login')));
        $this->assertSame(Decision::LOG, $d->action());
        $this->assertSame('reputation-modifier', $d->reason());
        $this->assertSame(0, $this->rep->lookupCalls); // mirror hit, no per-IP escalation

        // An IPv6 /128 inside a seeded /64 resolves after normalisation to /64.
        $this->store->seedMirror('2001:db8:abcd:1234::/64', ReputationVerdict::VERDICT_MALICIOUS);
        $d6 = $eng->evaluate($this->request('/login', '2001:db8:abcd:1234::99'), $this->profile('wordpress', array('/login')));
        $this->assertSame(Decision::LOG, $d6->action());
    }
}
