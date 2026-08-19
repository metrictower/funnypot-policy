<?php

namespace Funnypot\Policy\Tests\Engine;

use Funnypot\Policy\BotSignals;
use Funnypot\Policy\Decision;
use Funnypot\Policy\ReputationVerdict;
use Funnypot\Policy\Verdict;

/**
 * The S request-shape bot-signals as composite modifiers (decisions S2/S3/S5): never alone, FP-guards
 * first, fused with datacenter usage-type and the country modifier.
 */
final class BotSignalCompositeTest extends EngineTestCase
{
    private function cleanWithBot(BotSignals $bs)
    {
        return $this->verdict(Verdict::CLEAN, false, '', 0, Verdict::SEVERITY_LOW, true, $bs);
    }

    public function test_single_weak_signal_never_blocks_or_deceives()
    {
        // One weak signal (an empty User-Agent) only raises scrutiny; below the fusion threshold it does
        // not even reach log.
        $this->ev->scriptDefault($this->cleanWithBot($this->botSignals(BotSignals::UA_EMPTY, array())));
        $eng = $this->engine(array('posture' => 'honeypot'));
        $d = $eng->evaluate($this->request('/login', '203.0.113.7', array('User-Agent' => '')), $this->profile('wordpress', array('/login')));
        $this->assertNotSame(Decision::BLOCK, $d->action());
        $this->assertNotSame(Decision::DECEIVE, $d->action());
    }

    public function test_bot_signal_plus_datacenter_fuses()
    {
        // bot-shape alone -> allow (below threshold)
        $this->ev->scriptDefault($this->cleanWithBot($this->botSignals(BotSignals::UA_BROWSER, array('missing_accept_language'))));
        $botOnly = $this->engine(array('posture' => 'honeypot'));
        $this->assertSame(Decision::ALLOW, $botOnly->evaluate($this->request('/login'), $this->profile('wordpress', array('/login')))->action());

        // datacenter alone (no bot signals) -> allow (below threshold)
        $this->reset();
        $this->ev->scriptDefault($this->cleanWithBot(BotSignals::none()));
        $this->store->seedMirror('203.0.113.7', ReputationVerdict::VERDICT_SUSPICIOUS, null, 'datacenter');
        $dcOnly = $this->engine(array('posture' => 'honeypot'));
        $this->assertSame(Decision::ALLOW, $dcOnly->evaluate($this->request('/login', '203.0.113.7'), $this->profile('wordpress', array('/login')))->action());

        // bot-shape + datacenter -> fuses to log ("bot-UA + datacenter IP", S3)
        $this->reset();
        $this->ev->scriptDefault($this->cleanWithBot($this->botSignals(BotSignals::UA_BROWSER, array('missing_accept_language'))));
        $this->store->seedMirror('203.0.113.7', ReputationVerdict::VERDICT_SUSPICIOUS, null, 'datacenter');
        $fused = $this->engine(array('posture' => 'honeypot'));
        $d = $fused->evaluate($this->request('/login', '203.0.113.7'), $this->profile('wordpress', array('/login')));
        $this->assertSame(Decision::LOG, $d->action());
        $this->assertSame('bot-signal-composite', $d->reason());
    }

    public function test_country_modifier_also_fuses()
    {
        // bot-shape (1) + a scrutinised-country modifier (1) -> fuses to log (the modifiers add).
        $this->ev->scriptDefault($this->cleanWithBot($this->botSignals(BotSignals::UA_BROWSER, array('missing_accept_language'))));
        $this->geo->scriptIp('203.0.113.7', 'RU');
        $eng = $this->engine(array(
            'posture' => 'honeypot',
            'country' => array('enabled' => true, 'mode' => 'deny', 'countries' => array('RU'), 'action' => 'modifier'),
        ));
        $d = $eng->evaluate($this->request('/login', '203.0.113.7'), $this->profile('wordpress', array('/login')));
        $this->assertSame(Decision::LOG, $d->action());
    }

    public function test_anomaly_only_bot_shape_never_deceives()
    {
        // Many accumulated weak signals, but no specific matched signature -> at most log, never deceive.
        $this->ev->scriptDefault($this->cleanWithBot($this->botSignals(BotSignals::UA_SCRIPT, array('a', 'b', 'c', 'd'))));
        $eng = $this->engine(array('posture' => 'honeypot'));
        $d = $eng->evaluate($this->request('/login'), $this->profile('wordpress', array('/login')));
        $this->assertSame(Decision::LOG, $d->action());
        $this->assertSame(0, $this->ev->synthesizeCalls);
    }

    public function test_fp_guards_zero_signals_first()
    {
        $bot2 = $this->botSignals(BotSignals::UA_BROWSER, array('f1', 'f2')); // weakSignalCount = 2

        // Non-exempt no-header client still accrues the signal -> log.
        $this->ev->scriptDefault($this->cleanWithBot($bot2));
        $normal = $this->engine(array('posture' => 'honeypot'));
        $this->assertSame(Decision::LOG, $normal->evaluate($this->request('/login', '203.0.113.7', array('User-Agent' => 'Mozilla/5.0')), $this->profile('wordpress', array('/login')))->action());

        // Exempt UA (monitoring/API) -> bot-signals ZEROED -> allow.
        $this->reset();
        $this->ev->scriptDefault($this->cleanWithBot($bot2));
        $exemptUa = $this->engine(array('posture' => 'honeypot', 'bot_signals' => array('exempt_uas' => array('UptimeBot'))));
        $this->assertSame(Decision::ALLOW, $exemptUa->evaluate($this->request('/login', '203.0.113.7', array('User-Agent' => 'UptimeBot/1.0')), $this->profile('wordpress', array('/login')))->action());

        // Exempt path (*.map source-map fetch) -> bot-signals ZEROED -> allow.
        $this->reset();
        $this->ev->scriptDefault($this->cleanWithBot($bot2));
        $exemptPath = $this->engine(array('posture' => 'honeypot', 'bot_signals' => array('exempt_paths' => array('*.map'))));
        $this->assertSame(Decision::ALLOW, $exemptPath->evaluate($this->request('/app.js.map', '203.0.113.7'), $this->profile('wordpress', array('/app.js.map')))->action());
    }

    public function test_bot_signals_disabled_ignores_set()
    {
        $this->ev->scriptDefault($this->cleanWithBot($this->botSignals(BotSignals::UA_SCRIPT, array('a', 'b', 'c'))));
        $eng = $this->engine(array('posture' => 'honeypot', 'bot_signals' => array('enabled' => false)));
        $d = $eng->evaluate($this->request('/login'), $this->profile('wordpress', array('/login')));
        $this->assertSame(Decision::ALLOW, $d->action()); // the set contributes nothing
    }
}
