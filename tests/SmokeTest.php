<?php

namespace Funnypot\Policy\Tests;

use Funnypot\Policy\Version;
use PHPUnit\Framework\TestCase;

final class SmokeTest extends TestCase
{
    public function test_autoload_and_phpunit_wired()
    {
        $this->assertTrue(true);
        $this->assertSame('0.1.0-dev', Version::VERSION);
    }
}
