<?php

namespace Funnypot\Policy;

/**
 * Neutral, normalized request evidence the host adapter builds (design §2, Open item on body-shape).
 * Untyped props + docblocks (typed properties are 7.4+). The body-shape is a SHAPE only — never the raw
 * body — so nothing here can carry an attacker payload verbatim into a log/report (OAST hygiene §9).
 */
final class RequestEvidence
{
    /** @var string HTTP method, e.g. 'GET' */
    private $method;
    /** @var string request path (no query string) */
    private $path;
    /** @var array parsed query params (assoc) */
    private $query;
    /** @var array request headers, lower-cased keys (assoc) */
    private $headers;
    /** @var array body-shape descriptor (never the raw body) */
    private $bodyShape;
    /** @var string source IP (the actor) */
    private $ip;
    /** @var string|null a session/actor token when the adapter has one; else the IP is the actor id */
    private $actorId;
    /** @var string|null the visitor IP's ASN (enrichment), for ASN-lookup matching (Q1) */
    private $asn;

    /**
     * @param string      $method
     * @param string      $path
     * @param array       $query
     * @param array       $headers
     * @param array       $bodyShape
     * @param string      $ip
     * @param string|null $actorId
     * @param string|null $asn
     */
    public function __construct(string $method, string $path, array $query, array $headers, array $bodyShape, string $ip, $actorId = null, $asn = null)
    {
        $this->method = $method;
        $this->path = $path;
        $this->query = $query;
        $this->headers = self::lowerKeys($headers);
        $this->bodyShape = $bodyShape;
        $this->ip = $ip;
        $this->actorId = $actorId === null ? null : (string) $actorId;
        $this->asn = $asn === null ? null : (string) $asn;
    }

    private static function lowerKeys(array $headers)
    {
        $out = array();
        foreach ($headers as $k => $v) {
            $out[strtolower((string) $k)] = $v;
        }

        return $out;
    }

    public function method()
    {
        return $this->method;
    }

    public function path()
    {
        return $this->path;
    }

    public function query()
    {
        return $this->query;
    }

    public function headers()
    {
        return $this->headers;
    }

    /** Case-insensitive single header read, or null when absent. */
    public function header(string $name)
    {
        $k = strtolower($name);

        return isset($this->headers[$k]) ? $this->headers[$k] : null;
    }

    public function bodyShape()
    {
        return $this->bodyShape;
    }

    public function ip()
    {
        return $this->ip;
    }

    /** The seed/pin actor identity: the adapter's actor token when present, else the source IP. */
    public function actorId()
    {
        return $this->actorId !== null && $this->actorId !== '' ? $this->actorId : $this->ip;
    }

    public function asn()
    {
        return $this->asn;
    }
}
