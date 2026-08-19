<?php

namespace Funnypot\Policy;

/**
 * Declared stack + real-route oracle (design §2.7). DATA that flows in, not a service the engine calls
 * out to — it makes the position-blind engine context-aware without being context-coupled (M2). The
 * routeExists oracle is the single most important FP-safety input: a fake path must never collide with a
 * real one, so deception is FP-free by construction only where the counterfactual is a 404 (§5).
 *
 * The host supplies the two path sets (WP: is there a real handler? Laravel: does the router match? app:
 * is it a served file?). Untyped props + docblocks (typed properties are 7.4+).
 */
final class SiteProfile
{
    /** @var string declared stack, e.g. 'wordpress', 'laravel', 'static' */
    private $stack;
    /** @var array real routes that exist on this site (exact path set) */
    private $realRoutes;
    /** @var array sacrificial paths that provably don't exist here (exact path set) */
    private $sacrificialPaths;

    /**
     * @param string $stack
     * @param array  $realRoutes       paths that resolve to a route that actually exists
     * @param array  $sacrificialPaths paths that provably don't exist on this stack
     */
    public function __construct(string $stack, array $realRoutes = array(), array $sacrificialPaths = array())
    {
        $this->stack = $stack;
        $this->realRoutes = array_fill_keys(array_values($realRoutes), true);
        $this->sacrificialPaths = array_fill_keys(array_values($sacrificialPaths), true);
    }

    public function stack()
    {
        return $this->stack;
    }

    /** Does this path resolve to a route that actually EXISTS on this site? */
    public function routeExists(string $path)
    {
        return isset($this->realRoutes[$path]);
    }

    /** Is this path in the sacrificial set (provably doesn't exist here)? */
    public function isSacrificialPath(string $path)
    {
        return isset($this->sacrificialPaths[$path]);
    }
}
