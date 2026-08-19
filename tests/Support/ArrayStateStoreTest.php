<?php

namespace Funnypot\Policy\Tests\Support;

use Funnypot\Policy\ReputationVerdict;
use Funnypot\Policy\RuleState;
use PHPUnit\Framework\TestCase;

final class ArrayStateStoreTest extends TestCase
{
    /** @var FixedClock */
    private $clock;
    /** @var ArrayStateStore */
    private $store;

    protected function setUp(): void
    {
        $this->clock = new FixedClock(1000);
        $this->store = new ArrayStateStore($this->clock);
    }

    public function test_pin_roundtrip_and_ttl_expiry()
    {
        $this->store->setPin('203.0.113.7', 'deceive', 'seed-abc', 3600);
        $pin = $this->store->getPin('203.0.113.7');
        $this->assertNotNull($pin);
        $this->assertSame('deceive', $pin->action());
        $this->assertSame('seed-abc', $pin->seed());
        $this->assertSame(1000 + 3600, $pin->expiresAt());

        $this->clock->advance(3601);
        $this->assertNull($this->store->getPin('203.0.113.7'));
    }

    public function test_rule_state_put_get_and_bump()
    {
        $s = new RuleState(RuleState::TUNING, 500, 10);
        $this->store->putRuleState('rule-1', $s);
        $got = $this->store->ruleState('rule-1');
        $this->assertSame(RuleState::TUNING, $got->phase());
        $this->assertSame(10, $got->count());

        $this->store->bumpRuleEvaluated('rule-1', 5);
        $this->store->bumpRuleEvaluated('rule-1');
        $this->assertSame(16, $this->store->ruleState('rule-1')->count());
    }

    public function test_seen_verdict_dedup_window()
    {
        $key = 'dedup-key';
        $this->assertFalse($this->store->seenVerdict($key, 100)); // first: unseen
        $this->assertTrue($this->store->seenVerdict($key, 100));  // within window: seen

        $this->clock->advance(101);
        $this->assertFalse($this->store->seenVerdict($key, 100)); // window passed: unseen again
    }

    public function test_incr_and_buffer_and_aggregate()
    {
        $this->assertSame(1, $this->store->incrAlertCount('203.0.113.7', 600));
        $this->assertSame(2, $this->store->incrAlertCount('203.0.113.7', 600));
        $this->clock->advance(601);
        $this->assertSame(1, $this->store->incrAlertCount('203.0.113.7', 600)); // window rolled

        $this->assertSame(1, $this->store->bufferReport('grp', array('x' => 1), 900));
        $this->assertSame(2, $this->store->bufferReport('grp', array('x' => 2), 900));
        $drained = $this->store->takeReportBuffer();
        $this->assertArrayHasKey('grp', $drained);
        $this->assertCount(2, $drained['grp']);
        $this->assertSame(array(), $this->store->takeReportBuffer()); // drained

        $this->store->seedAggregate('sk', 'srcA', 120);
        $this->store->seedAggregate('sk', 'srcB', 100);
        $agg = $this->store->aggregateScore('sk', 90);
        $this->assertSame(2, $agg->distinctSourceCount());
        $this->assertSame(220, $agg->total());
    }

    public function test_mirror_verdict_lookup()
    {
        $this->store->seedMirror('203.0.113.7', ReputationVerdict::VERDICT_MALICIOUS);
        $hit = $this->store->mirrorVerdict('203.0.113.7');
        $this->assertNotNull($hit);
        $this->assertSame(ReputationVerdict::VERDICT_MALICIOUS, $hit->verdict());
        $this->assertSame(ReputationVerdict::SOURCE_MIRROR, $hit->source());

        $this->assertNull($this->store->mirrorVerdict('192.0.2.1')); // absent -> escalate signal
    }

    public function test_mirror_matches_by_cidr_containment_not_exact()
    {
        $this->store->seedMirror('203.0.113.0/24', ReputationVerdict::VERDICT_MALICIOUS);
        // Inside the /24 (not just the network address) matches by containment.
        $this->assertNotNull($this->store->mirrorVerdict('203.0.113.55'));
        $this->assertNotNull($this->store->mirrorVerdict('203.0.113.255'));
        // Outside the /24 does not match.
        $this->assertNull($this->store->mirrorVerdict('203.0.114.1'));
    }

    public function test_mirror_ipv6_normalised_to_64_before_lookup()
    {
        $this->store->seedMirror('2001:db8:abcd:1234::/64', ReputationVerdict::VERDICT_CRITICAL);
        // Two different /128s inside the same /64 both match (a /128-rotating attacker cannot evade).
        $this->assertNotNull($this->store->mirrorVerdict('2001:db8:abcd:1234::1'));
        $this->assertNotNull($this->store->mirrorVerdict('2001:db8:abcd:1234:ffff:ffff:ffff:ffff'));
        // A different /64 does not match.
        $this->assertNull($this->store->mirrorVerdict('2001:db8:abcd:9999::1'));
    }

    public function test_mirror_most_specific_match_wins()
    {
        $this->store->seedMirror('203.0.113.0/24', ReputationVerdict::VERDICT_SUSPICIOUS);
        $this->store->seedMirror('203.0.113.9', ReputationVerdict::VERDICT_CRITICAL); // exact IP
        // The exact-IP row (longest prefix) wins over its containing /24 (Q4).
        $hit = $this->store->mirrorVerdict('203.0.113.9');
        $this->assertSame(ReputationVerdict::VERDICT_CRITICAL, $hit->verdict());
        // An IP in the /24 but not the exact row still resolves from the range.
        $this->assertSame(ReputationVerdict::VERDICT_SUSPICIOUS, $this->store->mirrorVerdict('203.0.113.10')->verdict());
    }

    public function test_mirror_asn_row_matches_by_visitor_asn()
    {
        $this->store->seedMirror('AS64500', ReputationVerdict::VERDICT_MALICIOUS, null, 'datacenter');
        $this->store->seedIpAsn('198.51.100.20', 'AS64500');
        $hit = $this->store->mirrorVerdict('198.51.100.20');
        $this->assertNotNull($hit);
        $this->assertSame(ReputationVerdict::VERDICT_MALICIOUS, $hit->verdict());
        $this->assertSame('datacenter', $hit->usageType());
        // An IP with no ASN association does not match the ASN row.
        $this->assertNull($this->store->mirrorVerdict('198.51.100.99'));
    }

    public function test_decay_score_accumulates_and_decays()
    {
        $base = 600;
        $cap = 86400;
        $this->assertSame(10, $this->store->decayScore('actor', 10, $base, $cap));
        $this->assertSame(20, $this->store->decayScore('actor', 10, $base, $cap)); // no time passed
        $this->clock->advance(600); // one time-constant
        $after = $this->store->decayScore('actor', 0, $base, $cap);
        $this->assertLessThan(20, $after);       // decayed
        $this->assertGreaterThan(0, $after);     // not zero yet
        $this->clock->advance($cap);             // past the cap -> fully decayed
        $this->assertSame(5, $this->store->decayScore('actor', 5, $base, $cap));
    }
}
