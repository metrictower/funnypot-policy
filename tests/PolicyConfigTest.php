<?php

namespace Funnypot\Policy\Tests;

use Funnypot\Policy\Decision;
use Funnypot\Policy\PolicyConfig;
use Funnypot\Policy\Verdict;
use PHPUnit\Framework\TestCase;

final class PolicyConfigTest extends TestCase
{
    public function test_from_array_applies_defaults()
    {
        $c = PolicyConfig::fromArray(array());
        $this->assertSame(PolicyConfig::POSTURE_HONEYPOT, $c->posture());
        $this->assertTrue($c->positionEnabled('fallback'));
        $this->assertFalse($c->positionEnabled('before'));

        $this->assertSame(Decision::ALLOW, $c->actionFor(Verdict::CLEAN));
        $this->assertSame(Decision::LOG, $c->actionFor(Verdict::SUSPICIOUS));
        $this->assertSame(Decision::LOG, $c->actionFor(Verdict::AMBIENT));
        $this->assertSame(Decision::BLOCK, $c->actionFor(Verdict::ATTACK_CLASS));
        $this->assertSame(Decision::DECEIVE, $c->actionFor(Verdict::SCANNER_PROBE));
        $this->assertFalse($c->deceiveAmbientPaths());

        $rep = $c->reputation();
        $this->assertFalse($rep['enabled']);
        $this->assertSame(3600, $c->pin()['ttl_seconds']);
    }

    public function test_posture_presets_seed_position_and_ceiling()
    {
        $waf = PolicyConfig::fromArray(array('posture' => 'WAF'));
        $this->assertTrue($waf->positionEnabled('before'));
        $this->assertFalse($waf->positionEnabled('fallback'));
        $this->assertSame(Decision::BLOCK, $waf->ceiling(PolicyConfig::POSITION_BEFORE));

        $both = PolicyConfig::fromArray(array('posture' => 'both'));
        $this->assertTrue($both->positionEnabled('before'));
        $this->assertTrue($both->positionEnabled('fallback'));
        $this->assertSame(Decision::BLOCK, $both->ceiling(PolicyConfig::POSITION_BEFORE));
        $this->assertSame(Decision::DECEIVE, $both->ceiling(PolicyConfig::POSITION_FALLBACK));

        $hp = PolicyConfig::fromArray(array('posture' => 'honeypot'));
        $this->assertTrue($hp->positionEnabled('fallback'));
        $this->assertSame(Decision::LOG, $hp->ceiling(PolicyConfig::POSITION_BEFORE));      // observes before
        $this->assertSame(Decision::DECEIVE, $hp->ceiling(PolicyConfig::POSITION_FALLBACK)); // deceives at fallback
    }

    public function test_explicit_keys_override_preset()
    {
        $c = PolicyConfig::fromArray(array(
            'posture' => 'honeypot',
            'position' => array('before' => true), // override just the before knob
            'actions' => array('attack_class' => 'deceive'),
        ));
        $this->assertTrue($c->positionEnabled('before'));
        $this->assertTrue($c->positionEnabled('fallback')); // untouched preset value
        $this->assertSame(Decision::DECEIVE, $c->actionFor(Verdict::ATTACK_CLASS));
    }

    public function test_ambient_action_and_dedicated_permission_are_independent()
    {
        $actionOnly = PolicyConfig::fromArray(array('actions' => array('ambient' => Decision::DECEIVE)));
        $this->assertSame(Decision::DECEIVE, $actionOnly->actionFor(Verdict::AMBIENT));
        $this->assertFalse($actionOnly->deceiveAmbientPaths());

        $permissionOnly = PolicyConfig::fromArray(array('deceive_ambient_paths' => true));
        $this->assertSame(Decision::LOG, $permissionOnly->actionFor(Verdict::AMBIENT));
        $this->assertTrue($permissionOnly->deceiveAmbientPaths());
    }

    /** @dataProvider nonBooleanAmbientPermissionValues */
    public function test_ambient_deception_permission_accepts_only_boolean_true($value)
    {
        $c = PolicyConfig::fromArray(array('deceive_ambient_paths' => $value));
        $this->assertFalse($c->deceiveAmbientPaths());
    }

    public static function nonBooleanAmbientPermissionValues()
    {
        return array(
            'null' => array(null),
            'false' => array(false),
            'integer one' => array(1),
            'float one' => array(1.0),
            'true string' => array('true'),
            'false string' => array('false'),
            'one string' => array('1'),
            'array' => array(array(true)),
            'object' => array((object) array('enabled' => true)),
        );
    }

    public function test_as_primary_is_forced_false()
    {
        $c = PolicyConfig::fromArray(array('reputation' => array('as_primary' => true)));
        $this->assertFalse($c->reputation()['as_primary']); // hard false regardless of input
    }

    public function test_suppression_and_learn_defaults()
    {
        $c = PolicyConfig::fromArray(array());
        $s = $c->suppression();
        $this->assertSame(24, $s['verdict_dedup_hours']);
        $this->assertSame(100, $s['per_ip_alert_cap']);
        $this->assertSame(600, $s['per_ip_cap_window_s']);
        $this->assertSame(900, $s['buffer_ttl_s']);
        $this->assertSame(200, $s['score_gate']);
        $this->assertSame(2, $s['aggregate']['min_sources']);
        $this->assertSame(200, $s['aggregate']['min_total_score']);
        $this->assertSame(90, $s['aggregate']['window_days']);
        $this->assertSame(600, $s['decay']['base_ttl_s']);
        $this->assertSame(86400, $s['decay']['cap_ttl_s']);
        $this->assertSame(1, $s['decay']['inc_soft']);
        $this->assertSame(10, $s['decay']['inc_medium']);
        $this->assertSame(100, $s['decay']['inc_hard']);

        $l = $c->learn();
        $this->assertSame(7, $l['shadow_days']);
        $this->assertSame(5000, $l['shadow_min_reqs']);
    }

    public function test_country_defaults_off_modifier()
    {
        $c = PolicyConfig::fromArray(array());
        $co = $c->country();
        $this->assertFalse($co['enabled']);
        $this->assertSame('deny', $co['mode']);
        $this->assertSame(array(), $co['countries']);
        $this->assertSame('modifier', $co['action']);

        $c2 = PolicyConfig::fromArray(array('country' => array(
            'enabled' => true, 'mode' => 'allow', 'countries' => array('nl', 'de'), 'action' => 'block',
        )));
        $co2 = $c2->country();
        $this->assertTrue($co2['enabled']);
        $this->assertSame('allow', $co2['mode']);
        $this->assertSame(array('NL', 'DE'), $co2['countries']); // upper-cased
        $this->assertSame('block', $co2['action']);
    }

    public function test_bot_signals_defaults()
    {
        $c = PolicyConfig::fromArray(array());
        $b = $c->botSignals();
        $this->assertTrue($b['enabled']);
        $this->assertSame(array(), $b['exempt_uas']);
        $this->assertSame(array(), $b['exempt_paths']);
        $this->assertFalse($b['telemetry']);

        $c2 = PolicyConfig::fromArray(array('bot_signals' => array(
            'exempt_uas' => array('UptimeBot'), 'exempt_paths' => array('*.map'), 'telemetry' => true,
        )));
        $b2 = $c2->botSignals();
        $this->assertSame(array('UptimeBot'), $b2['exempt_uas']);
        $this->assertSame(array('*.map'), $b2['exempt_paths']);
        $this->assertTrue($b2['telemetry']);
    }

    public function test_allowlist_has_asns_key()
    {
        $c = PolicyConfig::fromArray(array());
        $al = $c->allowlist();
        $this->assertArrayHasKey('asns', $al);
        $this->assertSame(array(), $al['asns']);
        $this->assertArrayHasKey('ips', $al);
        $this->assertArrayHasKey('cidrs', $al);
        $this->assertArrayHasKey('safe_paths', $al);
    }
}
