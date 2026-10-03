<?php

namespace Funnypot\Policy\Tests\Engine;

use Funnypot\Policy\Decision;
use Funnypot\Policy\PolicyConfig;
use Funnypot\Policy\RuleState;
use Funnypot\Policy\Verdict;

/** The AMBIENT band is observable by default and deceptive only behind its dedicated permission. */
final class AmbientRuleTest extends EngineTestCase
{
    /** @dataProvider fallbackMatrix */
    public function test_fallback_matrix(array $config, $action, $reason, $syntheses)
    {
        $this->ev->scriptDefault($this->verdict(Verdict::AMBIENT, false, '', 0, Verdict::SEVERITY_LOW, false));
        $decision = $this->engine($config)->evaluate($this->request('/robots.txt'), $this->profile());

        $this->assertSame($action, $decision->action());
        $this->assertSame($reason, $decision->reason());
        $this->assertSame(1, $this->ev->classifyCalls);
        $this->assertSame($syntheses, $this->ev->synthesizeCalls);
    }

    public static function fallbackMatrix()
    {
        return array(
            'default permission absent' => array(array(), Decision::LOG, 'ambient', 0),
            'default action with permission' => array(
                array('deceive_ambient_paths' => true), Decision::LOG, 'ambient', 0,
            ),
            'deceive action permission absent' => array(
                array('actions' => array('ambient' => Decision::DECEIVE)), Decision::LOG, 'ambient', 0,
            ),
            'deceive action permission enabled' => array(
                array('actions' => array('ambient' => Decision::DECEIVE), 'deceive_ambient_paths' => true),
                Decision::DECEIVE, 'ambient', 1,
            ),
            'allow action permission absent' => array(
                array('actions' => array('ambient' => Decision::ALLOW)), Decision::ALLOW, 'allow', 0,
            ),
            'allow action permission enabled' => array(
                array('actions' => array('ambient' => Decision::ALLOW), 'deceive_ambient_paths' => true),
                Decision::DECEIVE, 'fallback-deceive', 1,
            ),
        );
    }

    public function test_real_route_without_specific_high_signal_never_earns_ambient_deception()
    {
        $this->ev->scriptDefault($this->verdict(Verdict::AMBIENT, false, '', 300, Verdict::SEVERITY_HIGH, true));
        $config = array(
            'posture' => PolicyConfig::POSTURE_WAF,
            'actions' => array('ambient' => Decision::DECEIVE),
            'deceive_ambient_paths' => true,
        );
        $decision = $this->engine($config)->evaluate(
            $this->request('/login'), $this->profile('wordpress', array('/login'))
        );

        $this->assertSame(Decision::BLOCK, $decision->action());
        $this->assertSame('ambient', $decision->reason());
        $this->assertSame(1, $this->ev->classifyCalls);
        $this->assertSame(0, $this->ev->synthesizeCalls);
    }

    public function test_real_route_allow_is_not_promoted_at_fallback()
    {
        $this->ev->scriptDefault($this->verdict(Verdict::AMBIENT, false, '', 0, Verdict::SEVERITY_LOW, true));
        $decision = $this->engine(array(
            'actions' => array('ambient' => Decision::ALLOW),
            'deceive_ambient_paths' => true,
        ))->evaluate($this->request('/login'), $this->profile('wordpress', array('/login')));

        $this->assertSame(Decision::ALLOW, $decision->action());
        $this->assertSame(0, $this->ev->synthesizeCalls);
    }

    /** @dataProvider realRouteRulePhases */
    public function test_real_route_high_signal_respects_rule_phase_and_posture(
        $posture,
        array $position,
        $phase,
        $action,
        $reason,
        $syntheses
    ) {
        $rule = 'ambient-rule';
        $this->store->putRuleState($rule, new RuleState($phase, 0, 0));
        $this->ev->scriptDefault($this->verdict(
            Verdict::AMBIENT, true, $rule, 300, Verdict::SEVERITY_HIGH, true
        ));
        $decision = $this->engine(array(
            'posture' => $posture,
            'position' => $position,
            'actions' => array('ambient' => Decision::DECEIVE),
            'deceive_ambient_paths' => true,
        ))->evaluate($this->request('/login'), $this->profile('wordpress', array('/login')));

        $this->assertSame($action, $decision->action());
        $this->assertSame($reason, $decision->reason());
        $this->assertSame(1, $this->ev->classifyCalls);
        $this->assertSame($syntheses, $this->ev->synthesizeCalls);
    }

    public static function realRouteRulePhases()
    {
        return array(
            'WAF enforced' => array(
                PolicyConfig::POSTURE_WAF, array('before' => true, 'fallback' => false),
                RuleState::ENFORCED, Decision::DECEIVE, 'ambient', 1,
            ),
            'WAF shadow' => array(
                PolicyConfig::POSTURE_WAF, array('before' => true, 'fallback' => false),
                RuleState::SHADOW, Decision::LOG, 'shadow', 0,
            ),
            'both enforced' => array(
                PolicyConfig::POSTURE_BOTH, array('before' => true, 'fallback' => true),
                RuleState::ENFORCED, Decision::DECEIVE, 'ambient', 1,
            ),
            'honeypot before enforced' => array(
                PolicyConfig::POSTURE_HONEYPOT, array('before' => true, 'fallback' => false),
                RuleState::ENFORCED, Decision::LOG, 'ambient', 0,
            ),
        );
    }

    /** @dataProvider flagStates */
    public function test_ambient_flag_never_reorders_allowlist_or_pin_precedence(array $flag)
    {
        $allowConfig = $flag + array('allowlist' => array('safe_paths' => array('/robots.txt')));
        $allow = $this->engine($allowConfig)->evaluate($this->request('/robots.txt'), $this->profile());
        $this->assertSame(Decision::ALLOW, $allow->action());
        $this->assertSame('safe-path', $allow->reason());
        $this->assertSame(0, $this->ev->classifyCalls);
        $this->assertSame(0, $this->ev->synthesizeCalls);

        $this->reset();
        $this->store->setPin('203.0.113.7', Decision::DECEIVE, 'existing-seed', 3600);
        $pin = $this->engine($flag)->evaluate($this->request('/robots.txt'), $this->profile());
        $this->assertSame(Decision::DECEIVE, $pin->action());
        $this->assertSame('pin', $pin->reason());
        $this->assertSame(0, $this->ev->classifyCalls);
        $this->assertSame(1, $this->ev->synthesizeCalls);
    }

    /** @dataProvider flagStates */
    public function test_non_ambient_explicit_and_fallback_deception_are_unchanged(array $flag)
    {
        $this->ev->scriptDefault($this->verdict(
            Verdict::SCANNER_PROBE, true, 'scanner-rule', 20, Verdict::SEVERITY_HIGH, false
        ));
        $explicit = $this->engine($flag)->evaluate($this->request('/probe'), $this->profile());
        $this->assertSame(Decision::DECEIVE, $explicit->action());
        $this->assertSame('scanner-probe', $explicit->reason());
        $this->assertSame(1, $this->ev->classifyCalls);
        $this->assertSame(1, $this->ev->synthesizeCalls);

        $this->reset();
        $this->ev->scriptDefault($this->verdict(Verdict::CLEAN, false, '', 0, Verdict::SEVERITY_LOW, false));
        $fallback = $this->engine($flag)->evaluate($this->request('/unknown'), $this->profile());
        $this->assertSame(Decision::DECEIVE, $fallback->action());
        $this->assertSame('fallback-deceive', $fallback->reason());
        $this->assertSame(1, $this->ev->classifyCalls);
        $this->assertSame(1, $this->ev->synthesizeCalls);
    }

    public static function flagStates()
    {
        return array(
            'missing' => array(array()),
            'false' => array(array('deceive_ambient_paths' => false)),
            'true' => array(array('deceive_ambient_paths' => true)),
        );
    }

    public function test_actual_ambient_is_always_soft_before_action_and_high_signal_severity()
    {
        $rule = 'ambient-report-rule';
        $this->store->putRuleState($rule, new RuleState(RuleState::ENFORCED, 0, 0));
        $this->ev->scriptDefault($this->verdict(
            Verdict::AMBIENT, true, $rule, 300, Verdict::SEVERITY_HIGH, true
        ));
        $base = array(
            'posture' => PolicyConfig::POSTURE_WAF,
            'actions' => array('ambient' => Decision::DECEIVE),
        );
        $blocked = $this->engine($base)->evaluate(
            $this->request('/login'), $this->profile('wordpress', array('/login'))
        );
        $this->assertSame(Decision::BLOCK, $blocked->action());
        $this->assertNull($blocked->report());
        $this->assertSame(1, $this->score('203.0.113.7'));

        $this->reset();
        $this->store->putRuleState($rule, new RuleState(RuleState::ENFORCED, 0, 0));
        $this->ev->scriptDefault($this->verdict(
            Verdict::AMBIENT, true, $rule, 300, Verdict::SEVERITY_HIGH, true
        ));
        $deceived = $this->engine($base + array('deceive_ambient_paths' => true))->evaluate(
            $this->request('/login'), $this->profile('wordpress', array('/login'))
        );
        $this->assertSame(Decision::DECEIVE, $deceived->action());
        $this->assertNull($deceived->report());
        $this->assertSame(1, $this->score('203.0.113.7'));

        $this->reset();
        $this->store->putRuleState('hard-rule', new RuleState(RuleState::ENFORCED, 0, 0));
        $this->ev->scriptDefault($this->verdict(
            Verdict::ATTACK_CLASS, true, 'hard-rule', 300, Verdict::SEVERITY_HIGH, true
        ));
        $hard = $this->engine(array('posture' => PolicyConfig::POSTURE_WAF))->evaluate(
            $this->request('/login'), $this->profile('wordpress', array('/login'))
        );
        $this->assertSame(Decision::BLOCK, $hard->action());
        $this->assertNotNull($hard->report());
        $this->assertSame(100, $this->score('203.0.113.7'));
    }

    private function score($ip)
    {
        return $this->store->decayScore($ip, 0, 600, 86400);
    }
}
