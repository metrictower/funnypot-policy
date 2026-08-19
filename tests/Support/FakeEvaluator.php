<?php

namespace Funnypot\Policy\Tests\Support;

use Funnypot\Policy\FakeResponse;
use Funnypot\Policy\Port\EvaluatorInterface;
use Funnypot\Policy\RequestEvidence;
use Funnypot\Policy\SiteProfile;
use Funnypot\Policy\Verdict;

/**
 * Scripts a Verdict for classify() and RECORDS whether synthesize() was called (and with which seed) —
 * so a test can prove synthesize runs ONLY on a deceive decision. Optional throw flags drive the
 * fail-safe matrix.
 */
final class FakeEvaluator implements EvaluatorInterface
{
    /** @var Verdict|null default verdict returned by classify() */
    private $default;
    /** @var array path => Verdict overrides */
    private $byPath = array();

    /** @var int number of classify() calls */
    public $classifyCalls = 0;
    /** @var array seeds passed to synthesize(), in order */
    public $synthesizeSeeds = array();
    /** @var int number of synthesize() calls */
    public $synthesizeCalls = 0;

    /** @var bool */
    public $throwOnClassify = false;
    /** @var bool */
    public $throwOnSynthesize = false;

    public function __construct($default = null)
    {
        $this->default = $default;
    }

    public function scriptDefault(Verdict $v)
    {
        $this->default = $v;

        return $this;
    }

    public function scriptPath(string $path, Verdict $v)
    {
        $this->byPath[$path] = $v;

        return $this;
    }

    public function classify(RequestEvidence $request, SiteProfile $profile)
    {
        $this->classifyCalls++;
        if ($this->throwOnClassify) {
            throw new \RuntimeException('classify boom');
        }
        $path = $request->path();
        if (isset($this->byPath[$path])) {
            return $this->byPath[$path];
        }
        if ($this->default instanceof Verdict) {
            return $this->default;
        }

        return new Verdict(Verdict::CLEAN, false, '', 0, Verdict::SEVERITY_LOW, $profile->routeExists($path));
    }

    public function synthesize(Verdict $verdict, SiteProfile $profile, string $seed)
    {
        $this->synthesizeCalls++;
        $this->synthesizeSeeds[] = $seed;
        if ($this->throwOnSynthesize) {
            throw new \RuntimeException('synthesize boom');
        }

        return new FakeResponse(200, array('X-Fake' => '1'), 'body-for-' . $seed, 'text/html');
    }

    public function lastSeed()
    {
        return empty($this->synthesizeSeeds) ? null : $this->synthesizeSeeds[count($this->synthesizeSeeds) - 1];
    }
}
