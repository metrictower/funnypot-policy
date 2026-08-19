<?php

namespace Funnypot\Policy\Tests\Support;

use Funnypot\Policy\Port\GeoIpInterface;

/**
 * Scripts an IP => country map and PROVES the contract: country() makes no network-shaped call
 * (networkCalls stays 0) and returns null for an unmapped IP (the geo-miss fall-through). Optional throw
 * flag drives the fail-safe matrix.
 */
final class FakeGeoIp implements GeoIpInterface
{
    /** @var array ip => ISO alpha-2 code */
    private $byIp = array();

    /** @var int number of country() calls */
    public $countryCalls = 0;
    /** @var int network-shaped calls — MUST stay 0 (the port contract forbids a network call) */
    public $networkCalls = 0;
    /** @var bool */
    public $throwOnCountry = false;

    public function scriptIp(string $ip, string $country)
    {
        $this->byIp[$ip] = $country;

        return $this;
    }

    public function country(string $ip)
    {
        $this->countryCalls++;
        if ($this->throwOnCountry) {
            throw new \RuntimeException('geoip boom');
        }
        return isset($this->byIp[$ip]) ? $this->byIp[$ip] : null;
    }
}
