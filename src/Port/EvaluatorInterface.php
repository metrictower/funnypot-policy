<?php

namespace Funnypot\Policy\Port;

use Funnypot\Policy\FakeResponse;
use Funnypot\Policy\RequestEvidence;
use Funnypot\Policy\SiteProfile;
use Funnypot\Policy\Verdict;

/**
 * The engine seam (design §2.1). Holds funnypot-core's two-phase engine. The policy engine calls
 * classify() LAST in the precedence (the most expensive gate) and calls synthesize() ONLY once the
 * policy has already chosen action=deceive. Position-blind, action-free: this port never decides an
 * action or knows the request's position — that is policy's job.
 */
interface EvaluatorInterface
{
    /**
     * Content-detection only (M2). Cheap, no I/O, no reputation, no position awareness.
     *
     * @param RequestEvidence $request normalized request
     * @param SiteProfile     $profile declared stack + real-route oracle
     * @return Verdict classification + matched signal + anomaly/severity + the S bot-signal set
     */
    public function classify(RequestEvidence $request, SiteProfile $profile);

    /**
     * Render a coherent fake. Invoked ONLY when the policy chose action=deceive. Deterministic in
     * $seed so a stateless engine gives a multi-step actor a coherent sequence (M2).
     *
     * @param Verdict     $verdict the verdict that justified deceiving
     * @param SiteProfile $profile
     * @param string      $seed    deterministic actor seed (§2.8)
     * @return FakeResponse opaque to the policy engine
     */
    public function synthesize(Verdict $verdict, SiteProfile $profile, string $seed);
}
