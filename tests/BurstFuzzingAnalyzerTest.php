<?php

namespace Funnypot\Policy\Tests;

use Funnypot\Policy\BurstFuzzingAnalyzer;
use Funnypot\Policy\BurstVerdict;
use PHPUnit\Framework\TestCase;

final class BurstFuzzingAnalyzerTest extends TestCase
{
    /** @var float */
    private $now = 1000.0;

    private function analyzer($reqPerSec = 25, $decoyBurst = 12)
    {
        $self = $this;

        return new BurstFuzzingAnalyzer(
            $reqPerSec,
            $decoyBurst,
            function () use ($self) {
                return $self->now;
            },
            function () {
                return str_repeat('a', 32); // fixed event id for deterministic tests
            }
        );
    }

    public function test_below_velocity_threshold_no_verdict()
    {
        $a = $this->analyzer(25);
        // 25 requests in the same instant == threshold (trips only on > 25). None should breach.
        for ($i = 0; $i < 25; $i++) {
            self::assertNull($a->observe('1.1.1.1'), "request {$i} under threshold");
        }
    }

    public function test_velocity_breach_yields_a_429_verdict()
    {
        $a = $this->analyzer(25);
        $verdict = null;
        for ($i = 0; $i < 30; $i++) {
            $v = $a->observe('2.2.2.2');
            if ($v !== null) {
                $verdict = $v;
                break;
            }
        }
        self::assertInstanceOf(BurstVerdict::class, $verdict);
        self::assertSame(429, $verdict->status());
        self::assertSame(3, $verdict->retryAfter(), 'first breach starts the exponential ladder at 3s');
        self::assertSame(32, strlen($verdict->eventId()));
        self::assertGreaterThan(25, $verdict->reqInWindow());
    }

    public function test_decoy_burst_breach_independent_of_velocity()
    {
        // Few requests overall (no velocity breach) but a burst of distinct decoy hits.
        $a = $this->analyzer(1000, 12);
        $verdict = null;
        for ($i = 0; $i < 14; $i++) {
            $this->now += 0.1; // slow pace: ~10 req/s, well under the 1000 velocity cap
            $v = $a->observe('3.3.3.3', true);
            if ($v !== null) {
                $verdict = $v;
                break;
            }
        }
        self::assertInstanceOf(BurstVerdict::class, $verdict);
        self::assertGreaterThan(12, $verdict->decoyInWindow());
    }

    public function test_retry_after_escalates_across_windows_then_caps()
    {
        $a = $this->analyzer(5);
        $seen = array();
        // Each round is a NEW velocity window (now advances) in which the source keeps flooding — i.e.
        // it ignored the prior Retry-After. The ladder climbs one step per window: 3,6,12,30,60, cap 60.
        for ($round = 0; $round < 8; $round++) {
            $this->now += 1.5; // a new window each round
            $v = null;
            for ($i = 0; $i < 7; $i++) {
                $r = $a->observe('4.4.4.4');
                if ($r !== null && $v === null) {
                    $v = $r; // the first verdict of the window = that window's level
                }
            }
            if ($v !== null) {
                $seen[] = $v->retryAfter();
            }
        }
        self::assertSame(3, $seen[0]);
        self::assertSame(6, $seen[1]);
        self::assertSame(12, $seen[2]);
        self::assertSame(30, $seen[3]);
        self::assertSame(60, $seen[4]);
        self::assertSame(60, $seen[count($seen) - 1], 'Retry-After caps at 60');
    }

    public function test_continuous_flood_climbs_the_ladder_to_the_cap()
    {
        // The realistic ffuf/gobuster case: a sustained flood with the clock advancing. It must CLIMB
        // past 3s (the worst offender escalates fastest), not stay pinned at 3s. Regression for the
        // inverted-escalation defect (gap-since-last-breach never crossed the window under a flood).
        $a = $this->analyzer(5);
        $seen = array();
        for ($step = 0; $step < 40; $step++) {
            $this->now += 0.2;              // 5 steps per second
            for ($i = 0; $i < 3; $i++) {    // ~15 req/s, over the 5 req/s threshold
                $r = $a->observe('x.x.x.x');
                if ($r !== null) {
                    $seen[] = $r->retryAfter();
                }
            }
        }
        self::assertContains(3, $seen, 'starts at 3s');
        self::assertContains(6, $seen, 'continuous flood climbs past the first level');
        self::assertContains(60, $seen, 'a sustained flood reaches the cap');
        self::assertSame(60, max($seen), 'Retry-After caps at 60');
    }

    public function test_single_burst_holds_one_level_does_not_self_escalate()
    {
        // A single fast burst in ONE window must stay at level 0 (3s) — escalation is across windows,
        // never per-request (a 7-request burst must not jump to 6s/12s).
        $a = $this->analyzer(5);
        $levels = array();
        for ($i = 0; $i < 10; $i++) {
            $r = $a->observe('9.9.9.9'); // all at the same instant (now not advanced)
            if ($r !== null) {
                $levels[] = $r->retryAfter();
            }
        }
        self::assertNotEmpty($levels);
        foreach ($levels as $ra) {
            self::assertSame(3, $ra, 'a single-window burst holds Retry-After at 3s');
        }
    }

    public function test_velocity_window_expires_old_requests()
    {
        $a = $this->analyzer(25);
        for ($i = 0; $i < 20; $i++) {
            self::assertNull($a->observe('5.5.5.5'));
        }
        $this->now += 10.0; // all prior requests age out of every window
        // A fresh burst from zero is needed to breach again.
        self::assertNull($a->observe('5.5.5.5'), 'old requests must not count toward the current window');
    }

    public function test_ladder_de_escalates_after_a_cooldown()
    {
        $a = $this->analyzer(5);
        // Climb the ladder across several windows of continued flooding.
        for ($round = 0; $round < 4; $round++) {
            $this->now += 1.5;
            for ($i = 0; $i < 7; $i++) {
                $a->observe('6.6.6.6');
            }
        }
        // Go quiet past the cooldown window; the first non-breaching request cools the ladder to 0.
        $this->now += 10.0;
        self::assertNull($a->observe('6.6.6.6'));
        // Flood again in a fresh window: Retry-After restarts at 3 (de-escalated), not the climbed level.
        $this->now += 1.5;
        $second = null;
        for ($i = 0; $i < 7; $i++) {
            $r = $a->observe('6.6.6.6');
            if ($r !== null && $second === null) {
                $second = $r;
            }
        }
        self::assertNotNull($second);
        self::assertSame(3, $second->retryAfter(), 'Retry-After de-escalates to 3s after a cooldown');
    }

    public function test_sources_are_independent()
    {
        $a = $this->analyzer(5);
        for ($i = 0; $i < 7; $i++) {
            $a->observe('7.7.7.7');
        }
        // A different source is unaffected (its own fresh window).
        for ($i = 0; $i < 5; $i++) {
            self::assertNull($a->observe('8.8.8.8'), "other source request {$i}");
        }
    }

    public function test_lru_bounds_tracked_sources()
    {
        $a = $this->analyzer(1000);
        for ($i = 0; $i < 4096 + 50; $i++) {
            $this->now += 0.001;
            $a->observe('src-' . $i);
        }
        self::assertLessThanOrEqual(4096, $a->trackedSources(), 'tracked sources are LRU-bounded');
    }
}
