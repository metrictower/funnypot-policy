<?php

namespace Funnypot\Policy\Tests;

use Funnypot\Policy\BotSignals;
use Funnypot\Policy\Decision;
use Funnypot\Policy\FakeResponse;
use Funnypot\Policy\ReportIntent;
use PHPUnit\Framework\TestCase;

final class DecisionTest extends TestCase
{
    private function fake()
    {
        return new FakeResponse(200, array(), 'body', 'text/html');
    }

    public function test_action_factories_and_getters()
    {
        $this->assertSame(Decision::ALLOW, Decision::allow()->action());
        $this->assertSame(Decision::LOG, Decision::log()->action());
        $this->assertSame(Decision::BLOCK, Decision::block(403)->action());

        $d = Decision::deceive($this->fake(), 3600);
        $this->assertSame(Decision::DECEIVE, $d->action());
        $this->assertInstanceOf(FakeResponse::class, $d->fakeHandle());
        $this->assertSame(3600, $d->pinTtl());
    }

    public function test_deceive_is_the_only_action_with_a_fake()
    {
        $this->assertNull(Decision::allow()->fakeHandle());
        $this->assertNull(Decision::log()->fakeHandle());
        $this->assertNull(Decision::block(403)->fakeHandle());
        $this->assertNotNull(Decision::deceive($this->fake())->fakeHandle());
    }

    public function test_status_is_settable_not_derived()
    {
        $this->assertSame(403, Decision::block(403)->status());
        $this->assertNull(Decision::allow()->status());
        $this->assertNull(Decision::log()->status());
    }

    public function test_reason_is_a_plain_label()
    {
        $this->assertSame('pin', Decision::allow('pin')->reason());
        $this->assertSame('sacrificial-path', Decision::deceive($this->fake(), null, 'sacrificial-path')->reason());
        $this->assertSame('ambient', Decision::log('ambient')->reason());
    }

    public function test_signature_shaped_reason_is_rejected()
    {
        $this->expectException(\InvalidArgumentException::class);
        // A signature-shaped string is not an allowed reason label (fingerprint-safety, §10).
        Decision::allow('SQLi UNION SELECT (CRS 942100)');
    }

    public function test_report_intent_carries_no_payload()
    {
        $intent = new ReportIntent('203.0.113.7', 'deceive', 'honeypot', 150, array('scanner'), 'dedup-1');
        $this->assertSame('203.0.113.7', $intent->ip());
        $this->assertSame('deceive', $intent->resultLabel());
        $this->assertSame('dedup-1', $intent->dedupKey());
        $this->assertSame(array('scanner'), $intent->categories());
        $this->assertNull($intent->signals()); // no signals unless supplied

        // There is no getter that could surface a raw body/signature — only opaque labels/scores.
        $getters = get_class_methods(ReportIntent::class);
        $this->assertNotContains('body', $getters);
        $this->assertNotContains('payload', $getters);
        $this->assertNotContains('signature', $getters);
    }

    public function test_report_intent_signals_opt_in_and_fingerprint_safe()
    {
        $bs = new BotSignals(BotSignals::UA_EMPTY, array('missing_accept_language'), 'ja4h-token');
        $signals = ReportIntent::signalsObject($bs, 25);

        $intent = new ReportIntent('203.0.113.7', 'log', 'honeypot', 40, array(ReportIntent::CATEGORY_BAD_BOT), 'dedup-2', 0.8, $signals);
        $this->assertTrue($intent->hasCategory(ReportIntent::CATEGORY_BAD_BOT));
        $this->assertSame(0.8, $intent->confidence()); // signal-weighted confidence (S4)

        $sig = $intent->signals();
        $this->assertSame(BotSignals::UA_EMPTY, $sig['ua_class']);
        $this->assertSame(array('missing_accept_language'), $sig['flags']);
        $this->assertSame('ja4h-token', $sig['fingerprint']);
        $this->assertSame(25, $sig['anomaly']);

        // The signals object holds flags/classes/tokens only — a serialized dump contains no raw payload.
        $dump = serialize($sig);
        $this->assertStringNotContainsString('UNION', $dump);
        $this->assertStringNotContainsString('SELECT', $dump);
    }

    public function test_category_constants_match_mainnet_slugs()
    {
        // Wire literal pin: prevents silent drift away from mainnet wire vocabulary.
        $this->assertSame('bad_bot', ReportIntent::CATEGORY_BAD_BOT);

        // Cross-repo boundary contract test against mainnet CategoryMap if in monorepo workspace.
        $categoryMapPath = dirname(__DIR__, 2) . '/funnypot-mainnet/app/Support/CategoryMap.php';
        if (!file_exists($categoryMapPath)) {
            $known = array('bad_bot');
            $this->assertContains(ReportIntent::CATEGORY_BAD_BOT, $known);
            return;
        }

        require_once $categoryMapPath;
        $constants = (new \ReflectionClass(ReportIntent::class))->getConstants();
        $categoryConstants = array();
        foreach ($constants as $name => $val) {
            if (strpos($name, 'CATEGORY_') === 0) {
                $categoryConstants[$name] = $val;
            }
        }

        $this->assertNotEmpty($categoryConstants, 'ReportIntent must define at least one CATEGORY_ constant');
        foreach ($categoryConstants as $name => $slug) {
            $this->assertTrue(
                \App\Support\CategoryMap::isSlug($slug),
                "ReportIntent::{$name} ('{$slug}') is not accepted by CategoryMap::isSlug() — mainnet will reject reports"
            );
        }
    }
}
