<?php

namespace Funnypot\Policy\Port;

/**
 * The country-resolution seam for the R country gate (design §2.6, §4 step 3a).
 *
 * CONTRACT: MUST NOT make a network call (M5 / decision R2). Country is resolved from a LOCAL GeoIP DB
 * (DB-IP Lite / GeoLite2), never a remote lookup. Resolves both IPv4 and IPv6. A deployment that does
 * not want a country gate injects NullGeoIp (always null) and the gate is a no-op.
 */
interface GeoIpInterface
{
    /**
     * ISO 3166-1 alpha-2 country code for an IP, from a LOCAL GeoIP DB. Returns null when the DB has no
     * answer (unknown country) — the gate then falls through, never blocks on a lookup miss (R4).
     *
     * @param string $ip IPv4 or IPv6
     * @return string|null two-letter country code, or null when unresolved
     */
    public function country(string $ip);
}
