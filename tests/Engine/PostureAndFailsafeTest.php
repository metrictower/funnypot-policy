<?php

namespace Funnypot\Policy\Tests\Engine;

use Funnypot\Policy\Decision;
use Funnypot\Policy\RuleState;
use Funnypot\Policy\Verdict;

/**
 * The §7 default-install posture (fallback deceives everything / before runs only FP-free gates), the
 * `both`-posture double-run short-circuit (M4), and the fail-safe invariant (every port throw ->
 * Decision::allow, never a 5xx — invariant 2).
 */
final class PostureAndFailsafeTest extends EngineTestCase
{
    public function test_fallback_deceives_everything_on_fresh_install()
    {
        // Default honeypot config, an unmatched request that reached the 404 fallback (no real route).
        $this->ev->scriptDefault($this->verdict(Verdict::CLEAN, false, '', 0, Verdict::SEVERITY_LOW, false));
        $eng = $this->engine(array('posture' => 'honeypot'));
        $d = $eng->evaluate($this->request('/random/unrouted'), $this->profile('wordpress'));
        $this->assertSame(Decision::DECEIVE, $d->action());
        $this->assertSame('fallback-deceive', $d->reason());
    }

    public function test_before_runs_only_fp_free_gates_rest_shadow()
    {
        // BEFORE-only position: sacrificial deception fires day-1; a real-route rule stays in SHADOW.
        $this->ev->scriptPath('/login', $this->verdict(Verdict::ATTACK_CLASS, true, 'r1', 90, Verdict::SEVERITY_HIGH, true));
        $eng = $this->engine(array('posture' => 'honeypot', 'position' => array('before' => true, 'fallback' => false)));
        $profile = $this->profile('wordpress', array('/login'), array('/wp-login.php'));

        $sac = $eng->evaluate($this->request('/wp-login.php'), $profile);
        $this->assertSame(Decision::DECEIVE, $sac->action()); // FP-free-by-construction, day-1

        $real = $eng->evaluate($this->request('/login', '198.51.100.9'), $profile);
        $this->assertSame(Decision::LOG, $real->action());     // real-route rule still shadow, no block
    }

    public function test_both_posture_short_circuits_on_allow()
    {
        // Case A: the before-run finds nothing (plain allow) -> the fallback run deceives everything.
        $this->ev->scriptDefault($this->verdict(Verdict::CLEAN, false, '', 0, Verdict::SEVERITY_LOW, false));
        $eng = $this->engine(array('posture' => 'both'));
        $d = $eng->evaluate($this->request('/unrouted'), $this->profile('wordpress'));
        $this->assertSame(Decision::DECEIVE, $d->action());
        $this->assertSame(2, $this->ev->classifyCalls); // both passes ran (before allowed -> fallback)

        // Case B: the before-run acts (block) -> NO double-run.
        $this->reset();
        $this->store->putRuleState('r1', new RuleState(RuleState::ENFORCED, 0, 0));
        $this->ev->scriptDefault($this->verdict(Verdict::ATTACK_CLASS, true, 'r1', 90, Verdict::SEVERITY_HIGH, true));
        $eng2 = $this->engine(array('posture' => 'both'));
        $d2 = $eng2->evaluate($this->request('/login'), $this->profile('wordpress', array('/login')));
        $this->assertSame(Decision::BLOCK, $d2->action());
        $this->assertSame(1, $this->ev->classifyCalls); // before acted -> no second pass
    }

    public function test_evaluator_throw_degrades_to_allow()
    {
        $this->ev->throwOnClassify = true;
        $d = $this->engine(array('posture' => 'WAF'))->evaluate($this->request('/x'), $this->profile('wordpress', array('/x')));
        $this->assertSame(Decision::ALLOW, $d->action());
        $this->assertSame('failsafe', $d->reason());
    }

    public function test_synthesize_throw_degrades_to_allow_not_500()
    {
        $this->ev->throwOnSynthesize = true;
        $d = $this->engine(array('posture' => 'honeypot'))->evaluate($this->request('/wp-login.php'), $this->profile('laravel', array(), array('/wp-login.php')));
        $this->assertSame(Decision::ALLOW, $d->action()); // a would-be deceive fails open, never a 500
    }

    public function test_store_throw_degrades_to_allow()
    {
        // The store is read on every request at precedence step 2 — the highest-probability throw site.
        $this->store->throwOnAccess = true;
        $d = $this->engine(array('posture' => 'WAF'))->evaluate($this->request('/x'), $this->profile('wordpress', array('/x')));
        $this->assertSame(Decision::ALLOW, $d->action());
    }

    public function test_reputation_throw_degrades_to_allow()
    {
        $this->rep->throwOnLookup = true;
        // reputation enabled + mirror-absent -> escalates to lookup, which throws.
        $d = $this->engine(array('posture' => 'WAF', 'reputation' => array('enabled' => true)))
            ->evaluate($this->request('/x', '198.51.100.9'), $this->profile('wordpress', array('/x')));
        $this->assertSame(Decision::ALLOW, $d->action());
    }

    public function test_geoip_throw_degrades_to_allow()
    {
        $this->geo->throwOnCountry = true;
        $d = $this->engine(array('country' => array('enabled' => true, 'mode' => 'deny', 'countries' => array('RU'))))
            ->evaluate($this->request('/x'), $this->profile('wordpress', array('/x')));
        $this->assertSame(Decision::ALLOW, $d->action()); // the country lookup can never take the site down
    }
}
