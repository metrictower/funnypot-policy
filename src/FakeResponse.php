<?php

namespace Funnypot\Policy;

/**
 * A rendered fake (design §2.1). OPAQUE to the policy engine — it flows back inside the Decision as the
 * fakeHandle for the adapter to emit; the policy engine never reads its bytes (reading them would couple
 * policy to mechanism). The status is app-chosen, never model-chosen (invariant 5); the Content-Type
 * must match the request (enforced in core's synthesizer). Untyped props + docblocks.
 */
final class FakeResponse
{
    /** @var int */
    private $status;
    /** @var array response headers */
    private $headers;
    /** @var string body bytes */
    private $body;
    /** @var string content type (must match the request) */
    private $contentType;

    /**
     * @param int    $status
     * @param array  $headers
     * @param string $body
     * @param string $contentType
     */
    public function __construct(int $status, array $headers, string $body, string $contentType)
    {
        $this->status = $status;
        $this->headers = $headers;
        $this->body = $body;
        $this->contentType = $contentType;
    }

    public function status()
    {
        return $this->status;
    }

    public function headers()
    {
        return $this->headers;
    }

    public function body()
    {
        return $this->body;
    }

    public function contentType()
    {
        return $this->contentType;
    }
}
