<?php

namespace Funnypot\Policy\Tests\Engine;

use Funnypot\Policy\Decision;
use Funnypot\Policy\Verdict;

/**
 * The deterministic seed + pin/TTL deception-consistency loop (design §2.8, M5) — the anti-unmask
 * property: a deceived actor's later requests replay the SAME action with the SAME seed.
 */
final class SeedAndPinTest extends EngineTestCase
{
    public function test_deceive_pins_seed_with_ttl()
    {
        $eng = $this->engine(array('posture' => 'honeypot', 'pin' => array('ttl_seconds' => 3600)));
        $req = $this->request('/wp-login.php');
        $expectedSeed = $eng->seedFor($req);

        $eng->evaluate($req, $this->profile('laravel', array(), array('/wp-login.php')));

        $pin = $this->store->getPin('203.0.113.7');
        $this->assertNotNull($pin);
        $this->assertSame(Decision::DECEIVE, $pin->action());
        $this->assertSame($expectedSeed, $pin->seed());
        $this->assertSame($this->clock->now() + 3600, $pin->expiresAt());
    }

    public function test_later_request_replays_same_seed()
    {
        $eng = $this->engine(array('posture' => 'honeypot'));
        $p = $this->profile('laravel', array(), array('/wp-login.php'));

        $eng->evaluate($this->request('/wp-login.php'), $p);        // first deceive pins seed S
        $eng->evaluate($this->request('/some/other/path'), $p);     // later request from the same actor

        $this->assertCount(2, $this->ev->synthesizeSeeds);
        $this->assertSame($this->ev->synthesizeSeeds[0], $this->ev->synthesizeSeeds[1]); // identical seed
    }

    public function test_pin_expires_and_reseeds()
    {
        $this->ev->scriptDefault($this->verdict(Verdict::SCANNER_PROBE, true, 'r1', 20, Verdict::SEVERITY_HIGH, false));
        $eng = $this->engine(array('posture' => 'honeypot', 'pin' => array('ttl_seconds' => 3600)));
        $p = $this->profile('laravel'); // no real routes -> counterfactual

        $eng->evaluate($this->request('/admin'), $p);
        $this->assertSame(1, $this->ev->classifyCalls);

        $eng->evaluate($this->request('/admin'), $p);   // within TTL -> pin replay, no fresh classify
        $this->assertSame(1, $this->ev->classifyCalls);

        $this->clock->advance(3601);                    // past the TTL -> pin gone
        $eng->evaluate($this->request('/admin'), $p);   // fresh evaluation runs classify again
        $this->assertSame(2, $this->ev->classifyCalls);
    }

    public function test_seed_is_deterministic_per_actor()
    {
        $eng = $this->engine();
        $a1 = $this->request('/x', '203.0.113.7');
        $a1b = $this->request('/y', '203.0.113.7');
        $a2 = $this->request('/x', '198.51.100.9');

        $this->assertSame($eng->seedFor($a1), $eng->seedFor($a1b)); // same actor -> same seed
        $this->assertNotSame($eng->seedFor($a1), $eng->seedFor($a2)); // different actor -> different seed
    }

    public function test_multi_path_probe_is_coherent()
    {
        $this->ev->scriptDefault($this->verdict(Verdict::SCANNER_PROBE, true, 'r1', 20, Verdict::SEVERITY_HIGH, false));
        $eng = $this->engine(array('posture' => 'honeypot'));
        $p = $this->profile('laravel'); // no real routes

        $eng->evaluate($this->request('/admin'), $p);
        $eng->evaluate($this->request('/admin/config'), $p);

        $this->assertCount(2, $this->ev->synthesizeSeeds);
        $this->assertSame($this->ev->synthesizeSeeds[0], $this->ev->synthesizeSeeds[1]); // one coherent seed
    }
}
