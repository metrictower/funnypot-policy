<?php

namespace Funnypot\Policy\Tests\Learn;

use Funnypot\Policy\ActorFacts;
use Funnypot\Policy\Decision;
use Funnypot\Policy\Learn\StateMachine;
use Funnypot\Policy\PolicyConfig;
use Funnypot\Policy\PolicyEngine;
use Funnypot\Policy\RequestEvidence;
use Funnypot\Policy\RuleState;
use Funnypot\Policy\SiteProfile;
use Funnypot\Policy\Tests\Support\ArrayStateStore;
use Funnypot\Policy\Tests\Support\FakeEvaluator;
use Funnypot\Policy\Tests\Support\FakeGeoIp;
use Funnypot\Policy\Tests\Support\FakeReputation;
use Funnypot\Policy\Tests\Support\FixedClock;
use Funnypot\Policy\Tests\Support\RecordingLogger;
use Funnypot\Policy\Verdict;
use PHPUnit\Framework\TestCase;

final class StateMachineTest extends TestCase
{
    /** @var FixedClock */
    private $clock;
    /** @var ArrayStateStore */
    private $store;
    /** @var RecordingLogger */
    private $log;

    protected function setUp(): void
    {
        $this->clock = new FixedClock(1000000000);
        $this->store = new ArrayStateStore($this->clock);
        $this->log = new RecordingLogger();
    }

    private function machine(array $config = array())
    {
        return new StateMachine($this->store, $this->clock, PolicyConfig::fromArray($config), $this->log);
    }

    private function shadowRule($ruleId, $count = 0)
    {
        $this->store->putRuleState($ruleId, new RuleState(RuleState::SHADOW, $this->clock->now(), $count));
    }

    public function test_shadow_forces_log_regardless_of_wanted_action()
    {
        // A real-route rule that "wants" block, but is in SHADOW -> forced to log (engine gating).
        $ev = new FakeEvaluator();
        $ev->scriptDefault(new Verdict(Verdict::ATTACK_CLASS, true, 'r1', 90, Verdict::SEVERITY_HIGH, true));
        $eng = new PolicyEngine($ev, new FakeReputation(), $this->store, new FakeGeoIp(), $this->clock, $this->log, PolicyConfig::fromArray(array('posture' => 'WAF')), 'salt');
        $this->shadowRule('r1');
        $d = $eng->evaluate(new RequestEvidence('GET', '/login', array(), array(), array(), '203.0.113.7'), new SiteProfile('wordpress', array('/login')));
        $this->assertSame(Decision::LOG, $d->action());
        $this->assertSame('shadow', $d->reason());
    }

    public function test_promotion_needs_both_dwell_and_volume()
    {
        $cfg = array('learn' => array('shadow_days' => 7, 'shadow_min_reqs' => 5000));

        // 7 days of dwell but too few requests -> stays SHADOW.
        $this->shadowRule('r1', 100);
        $this->clock->advance(7 * 86400 + 1);
        $this->assertFalse($this->machine($cfg)->eligibleForTuning('r1'));

        // Enough requests but too little dwell -> stays SHADOW.
        $this->clock->set(1000000000);
        $this->shadowRule('r2', 6000);
        $this->clock->advance(86400); // 1 day only
        $this->assertFalse($this->machine($cfg)->eligibleForTuning('r2'));

        // Both satisfied -> eligible for TUNING.
        $this->clock->set(1000000000);
        $this->shadowRule('r3', 6000);
        $this->clock->advance(7 * 86400 + 1);
        $m = $this->machine($cfg);
        $this->assertTrue($m->eligibleForTuning('r3'));
        $this->assertTrue($m->promoteToTuning('r3'));
        $this->assertSame(RuleState::TUNING, $this->store->ruleState('r3')->phase());
    }

    public function test_tuning_compiles_scoped_exclusion_not_global()
    {
        $this->store->putRuleState('r1', new RuleState(RuleState::TUNING, $this->clock->now(), 6000));
        $m = $this->machine();
        $legit = new ActorFacts(true, true, 0, 0); // auth + loads assets + no other matches

        $this->assertTrue($m->compileExclusion('r1', $legit, true, '/wp-admin/post.php', 'content'));
        $ex = $this->store->ruleState('r1')->exclusions();
        $this->assertCount(1, $ex);
        $this->assertSame('r1', $ex[0]['rule_id']);
        $this->assertSame('/wp-admin/post.php', $ex[0]['path_prefix']); // SCOPED to a path+param
        $this->assertSame('content', $ex[0]['param']);
        $this->assertArrayNotHasKey('global', $ex[0]); // never a global disable

        // A NON-legit actor's flag does not compile an exclusion.
        $notLegit = new ActorFacts(false, false, 3, 0);
        $this->assertFalse($m->compileExclusion('r1', $notLegit, false, '/x', 'p'));
    }

    public function test_baseline_excluded_ships_pre_excluded()
    {
        $m = $this->machine(array('learn' => array('baseline_excluded' => array('rule-fp-prone-1', 'rule-fp-prone-2'))));
        $m->applyBaseline();
        $this->assertNotEmpty($this->store->ruleState('rule-fp-prone-1')->exclusions());
        $this->assertNotEmpty($this->store->ruleState('rule-fp-prone-2')->exclusions());
    }

    public function test_human_approve_required_before_enforced()
    {
        $this->store->putRuleState('r1', new RuleState(RuleState::TUNING, $this->clock->now(), 6000));
        $m = $this->machine();

        $this->assertFalse($m->promoteToEnforced('r1')); // no approve yet
        $this->assertSame(RuleState::TUNING, $this->store->ruleState('r1')->phase());

        $m->approve('r1');
        $this->assertTrue($m->promoteToEnforced('r1'));
        $this->assertSame(RuleState::ENFORCED, $this->store->ruleState('r1')->phase());
    }

    public function test_enforced_auto_demotes_on_proven_legit_and_alerts()
    {
        $this->store->putRuleState('r1', new RuleState(RuleState::ENFORCED, $this->clock->now(), 6000, array(), true));
        $m = $this->machine();

        $this->assertTrue($m->demoteOnProvenLegit('r1')); // no human step
        $this->assertSame(RuleState::SHADOW, $this->store->ruleState('r1')->phase());
        $this->assertStringContainsString('demoted', $this->log->haystack()); // an alert was raised
    }

    public function test_global_kill_switch_demotes_all()
    {
        // An ENFORCED real-route rule, but the global kill-switch forces every rule to SHADOW at once.
        $this->store->putRuleState('r1', new RuleState(RuleState::ENFORCED, $this->clock->now(), 6000, array(), true));
        $ev = new FakeEvaluator();
        $ev->scriptDefault(new Verdict(Verdict::ATTACK_CLASS, true, 'r1', 90, Verdict::SEVERITY_HIGH, true));
        $eng = new PolicyEngine($ev, new FakeReputation(), $this->store, new FakeGeoIp(), $this->clock, $this->log, PolicyConfig::fromArray(array('posture' => 'WAF', 'learn' => array('kill_switch' => true))), 'salt');
        $d = $eng->evaluate(new RequestEvidence('GET', '/login', array(), array(), array(), '203.0.113.7'), new SiteProfile('wordpress', array('/login')));
        $this->assertSame(Decision::LOG, $d->action());
    }

    public function test_day1_sacrificial_path_auto_enforces_while_real_route_shadows()
    {
        $ev = new FakeEvaluator();
        // The real-route rule is scripted for the /login path; the sacrificial path is cheap-static.
        $ev->scriptPath('/login', new Verdict(Verdict::ATTACK_CLASS, true, 'r1', 90, Verdict::SEVERITY_HIGH, true));
        $eng = new PolicyEngine($ev, new FakeReputation(), $this->store, new FakeGeoIp(), $this->clock, $this->log, PolicyConfig::fromArray(array('posture' => 'honeypot')), 'salt');
        $profile = new SiteProfile('wordpress', array('/login'), array('/wp-login.php'));

        // Fresh config: every rule defaults to SHADOW. The sacrificial path deceives immediately (day-1).
        $sac = $eng->evaluate(new RequestEvidence('GET', '/wp-login.php', array(), array(), array(), '203.0.113.7'), $profile);
        $this->assertSame(Decision::DECEIVE, $sac->action());

        // The real-route attack-class rule is still only logged (shadow).
        $real = $eng->evaluate(new RequestEvidence('GET', '/login', array(), array(), array(), '198.51.100.9'), $profile);
        $this->assertSame(Decision::LOG, $real->action());
        $this->assertSame('shadow', $real->reason());
    }
}
