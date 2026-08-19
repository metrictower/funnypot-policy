<?php

namespace Funnypot\Policy\Tests\Engine;

use Funnypot\Policy\BotSignals;
use Funnypot\Policy\PolicyConfig;
use Funnypot\Policy\PolicyEngine;
use Funnypot\Policy\RequestEvidence;
use Funnypot\Policy\SiteProfile;
use Funnypot\Policy\Tests\Support\ArrayStateStore;
use Funnypot\Policy\Tests\Support\FakeEvaluator;
use Funnypot\Policy\Tests\Support\FakeGeoIp;
use Funnypot\Policy\Tests\Support\FakeReputation;
use Funnypot\Policy\Tests\Support\FixedClock;
use Funnypot\Policy\Tests\Support\RecordingLogger;
use Funnypot\Policy\Verdict;
use PHPUnit\Framework\TestCase;

/** Shared wiring for the engine phase tests: fresh fakes + an engine factory. */
abstract class EngineTestCase extends TestCase
{
    /** @var FakeEvaluator */
    protected $ev;
    /** @var FakeReputation */
    protected $rep;
    /** @var ArrayStateStore */
    protected $store;
    /** @var FakeGeoIp */
    protected $geo;
    /** @var FixedClock */
    protected $clock;
    /** @var RecordingLogger */
    protected $log;

    protected function setUp(): void
    {
        $this->clock = new FixedClock(1000000000);
        $this->ev = new FakeEvaluator();
        $this->rep = new FakeReputation();
        $this->store = new ArrayStateStore($this->clock);
        $this->geo = new FakeGeoIp();
        $this->log = new RecordingLogger();
    }

    /** Reinitialise all fakes for an independent scenario within one test method. */
    protected function reset()
    {
        $this->setUp();
    }

    protected function engine(array $config = array(), $siteSalt = 'salt')
    {
        return new PolicyEngine(
            $this->ev,
            $this->rep,
            $this->store,
            $this->geo,
            $this->clock,
            $this->log,
            PolicyConfig::fromArray($config),
            $siteSalt
        );
    }

    protected function request($path = '/', $ip = '203.0.113.7', array $headers = array(), $method = 'GET', $asn = null, $actorId = null)
    {
        return new RequestEvidence($method, $path, array(), $headers, array(), $ip, $actorId, $asn);
    }

    protected function profile($stack = 'wordpress', array $realRoutes = array(), array $sacrificial = array())
    {
        return new SiteProfile($stack, $realRoutes, $sacrificial);
    }

    protected function verdict($classification = Verdict::CLEAN, $matched = false, $signal = '', $anomaly = 0, $severity = Verdict::SEVERITY_LOW, $onRealRoute = true, $bot = null)
    {
        return new Verdict($classification, $matched, $signal, $anomaly, $severity, $onRealRoute, $bot);
    }

    protected function botSignals($uaClass = BotSignals::UA_BROWSER, array $flags = array(), $fp = '')
    {
        return new BotSignals($uaClass, $flags, $fp);
    }
}
