<?php

namespace Funnypot\Policy\Tests\Engine;

use Funnypot\Policy\Decision;
use Funnypot\Policy\RuleState;
use Funnypot\Policy\Verdict;

/**
 * The §5 deception governing rule: deceive where the counterfactual is a 404; above the block threshold
 * on real routes (via a specific matched signature); never in the uncertainty band.
 */
final class DeceptionRuleTest extends EngineTestCase
{
    private function enforce($ruleId)
    {
        $this->store->putRuleState($ruleId, new RuleState(RuleState::ENFORCED, 0, 0));
    }

    public function test_deceive_on_counterfactual_404()
    {
        // A specific match on a path that does not resolve to a real route (counterfactual is a 404).
        $this->ev->scriptDefault($this->verdict(Verdict::SCANNER_PROBE, true, 'r1', 20, Verdict::SEVERITY_HIGH, false));
        $eng = $this->engine(array('posture' => 'honeypot'));
        $d = $eng->evaluate($this->request('/.env'), $this->profile('laravel', array(), array()));
        $this->assertSame(Decision::DECEIVE, $d->action());
        $this->assertSame(1, $this->ev->synthesizeCalls);
    }

    public function test_deceive_on_specific_signal_past_threshold_real_route()
    {
        // Deceptive-WAF config: attack_class maps to deceive; a specific high-severity match on a REAL
        // route earns deception (deceive above block).
        $this->enforce('r1');
        $this->ev->scriptDefault($this->verdict(Verdict::ATTACK_CLASS, true, 'r1', 80, Verdict::SEVERITY_HIGH, true));
        $eng = $this->engine(array('posture' => 'WAF', 'actions' => array('attack_class' => 'deceive')));
        $d = $eng->evaluate($this->request('/login'), $this->profile('wordpress', array('/login')));
        $this->assertSame(Decision::DECEIVE, $d->action());
        $this->assertSame(1, $this->ev->synthesizeCalls);
    }

    public function test_anomaly_score_alone_never_deceives()
    {
        // High cumulative anomaly, but NO specific match, on a real route -> at most log/block.
        $this->enforce('');
        $this->ev->scriptDefault($this->verdict(Verdict::SUSPICIOUS, false, '', 300, Verdict::SEVERITY_HIGH, true));
        $eng = $this->engine(array('posture' => 'honeypot'));
        $d = $eng->evaluate($this->request('/login'), $this->profile('wordpress', array('/login')));
        $this->assertNotSame(Decision::DECEIVE, $d->action());
        $this->assertSame(0, $this->ev->synthesizeCalls); // no fake rendered
    }

    public function test_uncertainty_band_never_deceives()
    {
        $this->ev->scriptDefault($this->verdict(Verdict::SUSPICIOUS, false, '', 40, Verdict::SEVERITY_MEDIUM, true));

        // default honeypot -> log
        $hp = $this->engine(array('posture' => 'honeypot'));
        $this->assertSame(Decision::LOG, $hp->evaluate($this->request('/login'), $this->profile('wordpress', array('/login')))->action());

        // strict protect-mode (WAF, actions.suspicious=block) -> block, still never deceive
        $this->reset();
        $this->ev->scriptDefault($this->verdict(Verdict::SUSPICIOUS, false, '', 40, Verdict::SEVERITY_MEDIUM, true));
        $waf = $this->engine(array('posture' => 'WAF', 'actions' => array('suspicious' => 'block')));
        $d = $waf->evaluate($this->request('/login'), $this->profile('wordpress', array('/login')));
        $this->assertSame(Decision::BLOCK, $d->action());
    }

    public function test_synthesize_runs_only_on_deceive()
    {
        // A deceive case: synthesize runs exactly once.
        $this->ev->scriptDefault($this->verdict(Verdict::SCANNER_PROBE, true, 'r1', 20, Verdict::SEVERITY_HIGH, false));
        $eng = $this->engine(array('posture' => 'honeypot'));
        $eng->evaluate($this->request('/.env'), $this->profile('laravel'));
        $this->assertSame(1, $this->ev->synthesizeCalls);

        // A non-deceive case: synthesize never runs.
        $this->reset();
        $this->ev->scriptDefault($this->verdict(Verdict::SUSPICIOUS, false, '', 40, Verdict::SEVERITY_MEDIUM, true));
        $eng2 = $this->engine(array('posture' => 'honeypot'));
        $eng2->evaluate($this->request('/login'), $this->profile('wordpress', array('/login')));
        $this->assertSame(0, $this->ev->synthesizeCalls);
    }

    public function test_classify_is_the_last_gate()
    {
        $eng = $this->engine(array('posture' => 'honeypot'));

        // allowlist -> no classify
        $this->reset();
        $eng = $this->engine(array('posture' => 'honeypot', 'allowlist' => array('ips' => array('203.0.113.7'))));
        $eng->evaluate($this->request('/x'), $this->profile());
        $this->assertSame(0, $this->ev->classifyCalls);

        // pin -> no classify
        $this->reset();
        $eng = $this->engine(array('posture' => 'honeypot'));
        $this->store->setPin('203.0.113.7', Decision::DECEIVE, 'seed', 3600);
        $eng->evaluate($this->request('/x'), $this->profile());
        $this->assertSame(0, $this->ev->classifyCalls);

        // sacrificial -> no classify
        $this->reset();
        $eng = $this->engine(array('posture' => 'honeypot'));
        $eng->evaluate($this->request('/wp-login.php'), $this->profile('laravel', array(), array('/wp-login.php')));
        $this->assertSame(0, $this->ev->classifyCalls);
    }
}
