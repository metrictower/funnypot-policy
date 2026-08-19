<?php

namespace Funnypot\Policy;

/**
 * Aggregate score over a window (design §9). The aggregate-ban rule escalates only with >=2 DISTINCT
 * sources AND total_score >= 200 over a 90-day window — mirroring the mainnet >=2-distinct-source listing
 * gate (D4), so a lone source can never manufacture a ban. Untyped props + docblocks.
 */
final class AggScore
{
    /** @var array distinct source identifiers contributing in the window */
    private $sources;
    /** @var int summed score over the window */
    private $total;

    public function __construct(array $sources, int $total)
    {
        $this->sources = array_values(array_unique($sources));
        $this->total = $total;
    }

    public function sources()
    {
        return $this->sources;
    }

    public function distinctSourceCount()
    {
        return count($this->sources);
    }

    public function total()
    {
        return $this->total;
    }
}
