<?php

namespace Funnypot\Policy\Tests;

use Funnypot\Policy\BotSignals;
use Funnypot\Policy\Geo\NullGeoIp;
use Funnypot\Policy\Log\NullLogger;
use Funnypot\Policy\RequestEvidence;
use Funnypot\Policy\ReputationVerdict;
use Funnypot\Policy\SiteProfile;
use Funnypot\Policy\Tests\Support\FakeEvaluator;
use Funnypot\Policy\Tests\Support\FakeGeoIp;
use Funnypot\Policy\Tests\Support\FakeReputation;
use Funnypot\Policy\Tests\Support\RecordingLogger;
use Funnypot\Policy\Verdict;
use PHPUnit\Framework\TestCase;

final class PortsSmokeTest extends TestCase
{
    public function test_value_objects_roundtrip()
    {
        $e = new RequestEvidence('GET', '/wp-login.php', array('a' => '1'), array('User-Agent' => 'curl'), array('len' => 0), '203.0.113.7', null, 'AS64500');
        $this->assertSame('GET', $e->method());
        $this->assertSame('/wp-login.php', $e->path());
        $this->assertSame('curl', $e->header('user-agent'));
        $this->assertSame('curl', $e->header('User-Agent')); // case-insensitive
        $this->assertSame('203.0.113.7', $e->ip());
        $this->assertSame('203.0.113.7', $e->actorId()); // defaults to ip
        $this->assertSame('AS64500', $e->asn());

        $p = new SiteProfile('laravel', array('/login'), array('/wp-login.php', '/.env'));
        $this->assertSame('laravel', $p->stack());
        $this->assertTrue($p->routeExists('/login'));
        $this->assertFalse($p->routeExists('/wp-login.php'));
        $this->assertTrue($p->isSacrificialPath('/wp-login.php'));
        $this->assertFalse($p->isSacrificialPath('/login'));

        $bs = new BotSignals(BotSignals::UA_EMPTY, array('missing_accept_language', 'no_sec_fetch'), 'fp-token');
        $v = new Verdict(Verdict::ATTACK_CLASS, true, 'rule-opaque-123', 42, Verdict::SEVERITY_HIGH, true, $bs);
        $this->assertSame(Verdict::ATTACK_CLASS, $v->classification());
        $this->assertTrue($v->matched());
        $this->assertSame('rule-opaque-123', $v->signal());
        $this->assertSame('rule-opaque-123', $v->ruleId());
        $this->assertSame(42, $v->anomalyScore());
        $this->assertSame(Verdict::SEVERITY_HIGH, $v->severity());
        $this->assertTrue($v->onRealRoute());
        $this->assertSame(BotSignals::UA_EMPTY, $v->botSignals()->uaClass());
        $this->assertSame(3, $v->botSignals()->weakSignalCount()); // 2 flags + empty UA

        $r = new ReputationVerdict(ReputationVerdict::VERDICT_MALICIOUS, 88, ReputationVerdict::SOURCE_MIRROR, 'datacenter');
        $this->assertSame(ReputationVerdict::VERDICT_MALICIOUS, $r->verdict());
        $this->assertSame(88, $r->score());
        $this->assertSame(ReputationVerdict::SOURCE_MIRROR, $r->source());
        $this->assertSame('datacenter', $r->usageType()); // the S3 fusion input
        $this->assertTrue($r->isMalicious());
    }

    public function test_opaque_handles_do_not_require_signature_strings()
    {
        // A Verdict + its bot-signals construct with purely opaque tokens — no signature-shaped string
        // is required anywhere (fingerprint-safety by construction, §10 / S1).
        $bs = new BotSignals(BotSignals::UA_SCRIPT, array('missing_accept'), 'ja4h-abc');
        $v = new Verdict(Verdict::SUSPICIOUS, false, 'opaque-handle', 5, Verdict::SEVERITY_LOW, false, $bs);
        $this->assertSame('opaque-handle', $v->ruleId());
        $this->assertSame(array('missing_accept'), $v->botSignals()->flags());
        $this->assertSame('ja4h-abc', $v->botSignals()->fingerprint());
    }

    public function test_fake_evaluator_scripts_verdict_and_records_synthesize()
    {
        $p = new SiteProfile('static', array(), array('/.env'));
        $scripted = new Verdict(Verdict::ATTACK_CLASS, true, 'sig', 10, Verdict::SEVERITY_HIGH, false);
        $ev = new FakeEvaluator();
        $ev->scriptPath('/.env', $scripted);

        $e = new RequestEvidence('GET', '/.env', array(), array(), array(), '198.51.100.9');
        $this->assertSame($scripted, $ev->classify($e, $p));
        $this->assertSame(1, $ev->classifyCalls);

        // synthesize is not called until explicitly invoked, and it records the seed.
        $this->assertSame(0, $ev->synthesizeCalls);
        $ev->synthesize($scripted, $p, 'seed-xyz');
        $this->assertSame(1, $ev->synthesizeCalls);
        $this->assertSame('seed-xyz', $ev->lastSeed());
    }

    public function test_fake_reputation_never_calls_out()
    {
        $rep = new FakeReputation();
        $rep->scriptIp('203.0.113.7', new ReputationVerdict(ReputationVerdict::VERDICT_MALICIOUS, 90, ReputationVerdict::SOURCE_CACHE));

        $hit = $rep->lookup('203.0.113.7');
        $this->assertSame(ReputationVerdict::VERDICT_MALICIOUS, $hit->verdict());

        $miss = $rep->lookup('192.0.2.1');
        $this->assertSame(ReputationVerdict::VERDICT_UNKNOWN, $miss->verdict());
        $this->assertSame(ReputationVerdict::SOURCE_FAIL_OPEN, $miss->source());

        $this->assertSame(0, $rep->networkCalls); // never a network-shaped call on the request path
    }

    public function test_null_logger_is_noop()
    {
        $log = new NullLogger();
        $log->log('info', 'anything', array('k' => 'v'));
        $this->assertTrue(true); // no throw, no state
    }

    public function test_recording_logger_captures()
    {
        $log = new RecordingLogger();
        $log->log('warning', 'decision', array('reason' => 'pin'));
        $this->assertCount(1, $log->records);
        $this->assertSame('warning', $log->records[0][0]);
        $this->assertSame('decision', $log->records[0][1]);
        $this->assertSame(array('reason' => 'pin'), $log->records[0][2]);
    }

    public function test_geoip_local_only_and_miss_returns_null()
    {
        $geo = new FakeGeoIp();
        $geo->scriptIp('203.0.113.7', 'RU');
        $this->assertSame('RU', $geo->country('203.0.113.7'));
        $this->assertNull($geo->country('192.0.2.1')); // geo miss -> null (fall-through)
        $this->assertSame(0, $geo->networkCalls);      // no network call

        $null = new NullGeoIp();
        $this->assertNull($null->country('203.0.113.7')); // always null
    }

    public function test_engine_handle_is_carried_opaquely()
    {
        $v = new Verdict(Verdict::SCANNER_PROBE, true, 'rule-1', 10, Verdict::SEVERITY_HIGH, false, null, 'engine:bundle#7');

        self::assertSame('engine:bundle#7', $v->engineHandle(), 'the handle must survive the boundary byte-for-byte');
        self::assertSame('rule-1', $v->signal(), 'the handle must not be confused with the signal');
    }

    public function test_engine_handle_defaults_to_empty_so_existing_callers_are_unaffected()
    {
        $v = new Verdict(Verdict::CLEAN, false, '', 0, Verdict::SEVERITY_LOW, true);

        self::assertSame('', $v->engineHandle());
    }

}
