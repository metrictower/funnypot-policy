<?php

namespace Funnypot\Policy\Tests\Engine;

use Funnypot\Policy\Decision;

final class PrecedenceHeadTest extends EngineTestCase
{
    public function test_allowlisted_ip_allows()
    {
        $eng = $this->engine(array('allowlist' => array('ips' => array('203.0.113.7'))));
        $d = $eng->evaluate($this->request('/anything'), $this->profile());
        $this->assertSame(Decision::ALLOW, $d->action());
        $this->assertSame('allowlist', $d->reason());
        $this->assertSame(0, $this->ev->classifyCalls); // cheap gate short-circuits before classify
    }

    public function test_safe_path_allows()
    {
        $eng = $this->engine(array('allowlist' => array('safe_paths' => array('/health'))));
        $d = $eng->evaluate($this->request('/health'), $this->profile());
        $this->assertSame(Decision::ALLOW, $d->action());
        $this->assertSame('safe-path', $d->reason());
        $this->assertSame(0, $this->ev->classifyCalls);
    }

    public function test_self_ip_allows()
    {
        $eng = $this->engine(array('self_ips' => array('203.0.113.7')));
        $d = $eng->evaluate($this->request('/wp-login.php'), $this->profile());
        $this->assertSame(Decision::ALLOW, $d->action());
        $this->assertSame('self-ip', $d->reason());
        $this->assertSame(0, $this->ev->classifyCalls);
    }

    public function test_allowlist_matches_asn_and_cidr_by_containment()
    {
        $eng = $this->engine(array('allowlist' => array('cidrs' => array('203.0.113.0/24'), 'asns' => array('AS64500'))));
        // Inside the allowlisted /24 (containment, not exact-match).
        $d1 = $eng->evaluate($this->request('/x', '203.0.113.200'), $this->profile());
        $this->assertSame(Decision::ALLOW, $d1->action());
        // Under the allowlisted ASN.
        $d2 = $eng->evaluate($this->request('/x', '198.51.100.9', array(), 'GET', 'AS64500'), $this->profile());
        $this->assertSame(Decision::ALLOW, $d2->action());
        $this->assertSame(0, $this->ev->classifyCalls);
    }

    public function test_pin_replays_action_and_seed()
    {
        $eng = $this->engine();
        $this->store->setPin('203.0.113.7', Decision::DECEIVE, 'PINNED-SEED', 3600);
        $d = $eng->evaluate($this->request('/admin'), $this->profile());
        $this->assertSame(Decision::DECEIVE, $d->action());
        $this->assertSame('pin', $d->reason());
        $this->assertSame('PINNED-SEED', $this->ev->lastSeed()); // the PINNED seed, not a fresh one
        $this->assertSame(0, $this->ev->classifyCalls);
    }

    public function test_blocklist_blocks_in_waf_mode()
    {
        $eng = $this->engine(array('posture' => 'WAF'));
        $this->store->block('203.0.113.7');
        $d = $eng->evaluate($this->request('/x'), $this->profile());
        $this->assertSame(Decision::BLOCK, $d->action());
        $this->assertSame(403, $d->status());
        $this->assertSame('blocklist', $d->reason());
    }

    public function test_blocklist_deceives_in_honeypot_mode()
    {
        $eng = $this->engine(array('posture' => 'honeypot'));
        $this->store->block('203.0.113.7');
        $d = $eng->evaluate($this->request('/x'), $this->profile());
        $this->assertSame(Decision::DECEIVE, $d->action());
        $this->assertSame(0, $this->ev->classifyCalls);
    }

    public function test_sacrificial_path_deceives_day_one_no_engine_call()
    {
        $eng = $this->engine(array('posture' => 'honeypot'));
        $p = $this->profile('laravel', array(), array('/wp-login.php'));
        $d = $eng->evaluate($this->request('/wp-login.php'), $p);
        $this->assertSame(Decision::DECEIVE, $d->action());
        $this->assertSame('sacrificial-path', $d->reason());
        $this->assertSame(0, $this->ev->classifyCalls);   // NO engine classify
        $this->assertSame(1, $this->ev->synthesizeCalls);  // but a fake IS synthesized
    }

    public function test_malicious_ua_exact_match()
    {
        $eng = $this->engine(array('posture' => 'WAF'));
        $d = $eng->evaluate($this->request('/x', '203.0.113.7', array('User-Agent' => 'sqlmap/1.5')), $this->profile());
        $this->assertSame(Decision::BLOCK, $d->action());
        $this->assertSame('malicious-ua', $d->reason());
        $this->assertSame(0, $this->ev->classifyCalls);
    }

    public function test_country_deny_modifier_falls_through_and_arms_scrutiny()
    {
        $eng = $this->engine(array('country' => array('enabled' => true, 'mode' => 'deny', 'countries' => array('RU'), 'action' => 'modifier')));
        $this->geo->scriptIp('203.0.113.7', 'RU');
        $d = $eng->evaluate($this->request('/x'), $this->profile('wordpress', array('/x')));
        $this->assertNotSame(Decision::BLOCK, $d->action());
        $this->assertNotSame(Decision::DECEIVE, $d->action()); // modifier does not itself act
        $this->assertGreaterThan(0, $this->geo->countryCalls);
        $this->assertSame(0, $this->geo->networkCalls); // local DB, no network call
        $this->assertStringContainsString('country', $this->log->haystack());
    }

    public function test_country_deny_block_is_opt_in_and_blocks()
    {
        $eng = $this->engine(array('posture' => 'WAF', 'country' => array('enabled' => true, 'mode' => 'deny', 'countries' => array('RU'), 'action' => 'block')));
        $this->geo->scriptIp('203.0.113.7', 'RU');
        $d = $eng->evaluate($this->request('/x'), $this->profile('wordpress', array('/x')));
        $this->assertSame(Decision::BLOCK, $d->action());
        $this->assertSame('country', $d->reason());
    }

    public function test_country_allow_posture_acts_on_non_listed()
    {
        $eng = $this->engine(array('country' => array('enabled' => true, 'mode' => 'allow', 'countries' => array('NL'), 'action' => 'deceive')));
        $this->geo->scriptIp('203.0.113.7', 'RU'); // non-listed -> acted on
        $this->geo->scriptIp('203.0.113.8', 'NL'); // listed -> passes freely
        $acted = $eng->evaluate($this->request('/x', '203.0.113.7'), $this->profile('wordpress', array('/x')));
        $this->assertSame(Decision::DECEIVE, $acted->action());
        $passed = $eng->evaluate($this->request('/x', '203.0.113.8'), $this->profile('wordpress', array('/x')));
        $this->assertNotSame(Decision::DECEIVE, $passed->action()); // listed country falls through
    }

    public function test_country_geo_miss_falls_through()
    {
        $eng = $this->engine(array('country' => array('enabled' => true, 'mode' => 'deny', 'countries' => array('RU'), 'action' => 'block')));
        // No scripted country -> FakeGeoIp returns null (a geo miss).
        $d = $eng->evaluate($this->request('/x'), $this->profile('wordpress', array('/x')));
        $this->assertNotSame(Decision::BLOCK, $d->action());
        $this->assertNotSame(Decision::DECEIVE, $d->action());
    }

    public function test_country_gate_disabled_is_noop()
    {
        $eng = $this->engine(array('country' => array('enabled' => false)));
        $eng->evaluate($this->request('/x'), $this->profile('wordpress', array('/x')));
        $this->assertSame(0, $this->geo->countryCalls); // disabled -> geo.country never called
    }

    public function test_nothing_matches_falls_through_to_allow()
    {
        $eng = $this->engine(array('posture' => 'WAF')); // before position, no fallback-deceive
        $d = $eng->evaluate($this->request('/x'), $this->profile('wordpress', array('/x')));
        $this->assertSame(Decision::ALLOW, $d->action());
    }
}
