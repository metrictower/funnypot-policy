<?php

namespace Funnypot\Policy\Tests\Report;

use Funnypot\Policy\BotSignals;
use Funnypot\Policy\PolicyConfig;
use Funnypot\Policy\ReportIntent;
use Funnypot\Policy\Report\Suppressor;
use Funnypot\Policy\Tests\Support\ArrayStateStore;
use Funnypot\Policy\Tests\Support\FixedClock;
use Funnypot\Policy\Tests\Support\RecordingLogger;
use PHPUnit\Framework\TestCase;

final class SuppressionTest extends TestCase
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

    private function suppressor(array $config = array())
    {
        return new Suppressor($this->store, $this->clock, PolicyConfig::fromArray($config), $this->log);
    }

    public function test_verdict_dedup_one_per_24h()
    {
        $s = $this->suppressor();
        // Hard tells bypass the score gate, isolating the dedup layer.
        $this->assertNotNull($s->consider('203.0.113.7', 'block', 'honeypot', Suppressor::SEV_HARD));
        $this->assertNull($s->consider('203.0.113.7', 'block', 'honeypot', Suppressor::SEV_HARD)); // identical -> once/24h
        $this->assertNotNull($s->consider('203.0.113.7', 'block', 'mainnet', Suppressor::SEV_HARD)); // distinct source -> emits

        // After the window passes, the identical verdict emits again.
        $this->clock->advance(24 * 3600 + 1);
        $this->assertNotNull($s->consider('203.0.113.7', 'block', 'honeypot', Suppressor::SEV_HARD));
    }

    public function test_per_ip_cap_stops_at_100_per_600s()
    {
        $s = $this->suppressor();
        // Distinct result labels bypass dedup; hard tells bypass the gate — isolating the per-IP cap.
        for ($i = 1; $i <= 100; $i++) {
            $this->assertNotNull($s->consider('203.0.113.7', 'r' . $i, 'honeypot', Suppressor::SEV_HARD), "alert $i within cap");
        }
        $this->assertNull($s->consider('203.0.113.7', 'r101', 'honeypot', Suppressor::SEV_HARD)); // 101st suppressed
    }

    public function test_buffer_collapses_burst_to_one_with_count()
    {
        $s = $this->suppressor();
        for ($i = 0; $i < 5; $i++) {
            $intent = new ReportIntent('203.0.113.' . $i, 'deceive', 'honeypot', 10, array(), 'k' . $i);
            $s->buffer('scan-burst', $intent);
        }
        $drained = $s->drain();
        $this->assertCount(1, $drained);                                    // one collapsed message
        $this->assertStringContainsString('(x5)', $drained[0]->resultLabel()); // carrying the repeat count
        $this->assertSame(array(), $s->drain());                            // drained
    }

    public function test_score_gate_suppresses_below_200()
    {
        $s = $this->suppressor();
        // Accumulate medium (+10) events; below the 200 gate each is recorded but not alerted.
        for ($i = 1; $i <= 19; $i++) {
            $this->assertNull($s->consider('203.0.113.7', 'log', 'honeypot', Suppressor::SEV_MEDIUM), "below gate at step $i");
        }
        // The 20th crosses 200 -> alerts.
        $this->assertNotNull($s->consider('203.0.113.7', 'log', 'honeypot', Suppressor::SEV_MEDIUM));
    }

    public function test_decay_increments_and_read_time_decay()
    {
        $s = $this->suppressor();

        // A hard tell crosses the gate instantly (score 100 < 200, but hard-tell bypasses).
        $this->assertNotNull($s->consider('198.51.100.1', 'block', 'honeypot', Suppressor::SEV_HARD));

        // Soft/medium events accumulate but stay below the gate.
        $this->assertNull($s->consider('203.0.113.7', 'log', 'honeypot', Suppressor::SEV_MEDIUM)); // score 10
        $before = $this->store->decayScore('203.0.113.7', 0, 600, 86400);
        $this->assertGreaterThan(0, $before);

        // Read-time decay: after advancing the clock the accumulated score drifts down (no sweep).
        $this->clock->advance(1200);
        $after = $this->store->decayScore('203.0.113.7', 0, 600, 86400);
        $this->assertLessThan($before, $after);
    }

    public function test_aggregate_ban_needs_two_sources_and_200_over_90d()
    {
        $s = $this->suppressor();

        // One source at >=200 -> no ban (a lone source can never manufacture a ban).
        $this->store->seedAggregate('203.0.113.7', 'srcA', 250);
        $this->assertFalse($s->aggregateBan('203.0.113.7'));

        // >=2 distinct sources AND >=200 within 90d -> ban recommendation.
        $this->store->seedAggregate('203.0.113.7', 'srcB', 50);
        $this->assertTrue($s->aggregateBan('203.0.113.7'));

        // Contributions outside the 90-day window do not count.
        $old = $this->clock->now() - (91 * 86400);
        $this->store->seedAggregate('198.51.100.9', 'srcA', 300, $old);
        $this->store->seedAggregate('198.51.100.9', 'srcB', 300, $old);
        $this->assertFalse($s->aggregateBan('198.51.100.9'));
    }

    public function test_backstops_suppress_at_every_mutating_point()
    {
        $s = $this->suppressor(array(
            'allowlist' => array('ips' => array('203.0.113.7'), 'cidrs' => array('10.0.0.0/8'), 'safe_paths' => array('/health')),
            'self_ips' => array('192.0.2.50'),
        ));
        // Even a hard tell is suppressed for an allowlisted / self / safe-path actor.
        $this->assertNull($s->consider('203.0.113.7', 'block', 'honeypot', Suppressor::SEV_HARD));            // allowlisted ip
        $this->assertNull($s->consider('10.1.2.3', 'block', 'honeypot', Suppressor::SEV_HARD));               // allowlisted cidr
        $this->assertNull($s->consider('192.0.2.50', 'block', 'honeypot', Suppressor::SEV_HARD));             // self ip
        $this->assertNull($s->consider('198.51.100.9', 'block', 'honeypot', Suppressor::SEV_HARD, array('path' => '/health'))); // safe path
    }

    public function test_oast_shaped_path_is_redacted_never_verbatim()
    {
        $s = $this->suppressor();
        $this->assertSame('[redacted-url]', $s->redactOast('http://evil.oast.site/x'));
        $this->assertSame('[redacted-url]', $s->redactOast('//evil.example/callback'));
        $this->assertSame('/normal/path', $s->redactOast('/normal/path'));

        // A consider() carrying an OAST-shaped path never leaks the live URL into the intent or the log.
        $oast = 'http://attacker.oast.example/beacon';
        $intent = $s->consider('203.0.113.7', 'deceive', 'honeypot', Suppressor::SEV_HARD, array('path' => $oast));
        $this->assertNotNull($intent);
        $this->assertStringNotContainsString('attacker.oast.example', serialize($intent));
        $this->assertStringNotContainsString('attacker.oast.example', $this->log->haystack());
    }

    public function test_bad_bot_category_and_opt_in_signals()
    {
        $bot = new BotSignals(BotSignals::UA_EMPTY, array('missing_accept_language'), 'ja4h-token');

        // telemetry OFF: bad-bot category + confidence present, but NO signals object.
        $s = $this->suppressor(array('bot_signals' => array('telemetry' => false)));
        $intent = $s->consider('203.0.113.7', 'log', 'honeypot', Suppressor::SEV_HARD, array('botSignals' => $bot, 'anomaly' => 25));
        $this->assertTrue($intent->hasCategory(ReportIntent::CATEGORY_BAD_BOT));
        $this->assertGreaterThan(0, $intent->confidence()); // signal-weighted (S4)
        $this->assertNull($intent->signals());

        // telemetry ON: the fingerprint-safe signals object rides the report (T4/T5).
        $this->setUp();
        $s2 = $this->suppressor(array('bot_signals' => array('telemetry' => true)));
        $intent2 = $s2->consider('203.0.113.7', 'log', 'honeypot', Suppressor::SEV_HARD, array('botSignals' => $bot, 'anomaly' => 25));
        $sig = $intent2->signals();
        $this->assertNotNull($sig);
        $this->assertSame(BotSignals::UA_EMPTY, $sig['ua_class']);
        $this->assertSame(array('missing_accept_language'), $sig['flags']);
        $this->assertSame('ja4h-token', $sig['fingerprint']);
        $this->assertStringNotContainsString('UNION', serialize($sig)); // no raw payload / signature
    }
}
