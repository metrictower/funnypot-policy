<?php

namespace Funnypot\Policy\Geo;

use Funnypot\Policy\Port\GeoIpInterface;

/**
 * The shipped default GeoIpInterface: always null (design §2.6). With this injected, the country gate
 * is inert — every lookup is a miss and the gate falls through. A deployment that wants a country
 * policy injects a real implementation over a local GeoIP DB instead.
 */
final class NullGeoIp implements GeoIpInterface
{
    public function country(string $ip)
    {
        return null;
    }
}
