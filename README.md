# funnypot-policy

> **Not sure you're in the right place?**
> - Want a ready-to-run **honeypot box** to deploy → [funnypot](https://github.com/metrictower/funnypot)
> - Protecting a **Laravel** app → [funnypot-laravel](https://github.com/metrictower/funnypot-laravel)
> - Protecting a **WordPress** site → [funnypot-wordpress](https://github.com/metrictower/funnypot-wordpress)
> - Embedding the deception/detection **engine** in your own PHP / PSR-15 app → [funnypot-core](https://github.com/metrictower/funnypot-core)
> - Querying / reporting to the **IP-reputation service** from code (the SDK) → [funnypot-mainnet-client](https://github.com/metrictower/funnypot-mainnet-client)
> - Building on the low-level **decision/policy engine** → funnypot-policy **← you are here**

The **framework-free, PHP 7.3+ position-blind decision engine** behind the funnypot WAF / honeypot
extensions. It takes normalized request evidence in and returns exactly one `Decision`
(`allow` / `log` / `block` / `deceive`) out — **pure data, no side effects**. The host adapter
executes that `Decision`.

## Who this is for

Most people never install this directly. It is consumed through the framework adapters —
[funnypot-wordpress](https://github.com/metrictower/funnypot-wordpress) and
[funnypot-laravel](https://github.com/metrictower/funnypot-laravel) — which normalize the request,
call the engine, and perform the effect. Install it directly only when you are **building your own
adapter** for another host and want the same audited decision logic.

```bash
composer require metrictower/funnypot-policy
```

## The mechanism / policy / execution split

Three layers, one responsibility each:

| Concern | Owner | Shape |
|---|---|---|
| **Mechanism** — detect an attack, render a fake | funnypot-core | `classify()` + `synthesize()` (content-only, position-blind) |
| **Policy** — *whether* / *what action* / *where* | **funnypot-policy** (here) | `evaluate(evidence) → Decision` (position-aware, side-effect-free) |
| **Execution** — normalize, run the Decision, persist, hook | the host adapter | thin framework glue |

Because policy owns the opinions and the host owns the effects, "honeypot vs WAF" and "before vs
fallback" are a **config choice, never a code change**.

## The engine

`PolicyEngine::evaluate(RequestEvidence $e, SiteProfile $p): Decision` is the single entry point. It
**never throws on the request path** — every port fault degrades to `Decision::allow` (fail-open; a
500 is itself a tell). A `Decision` carries an app-chosen status (never model-chosen) and a `reason`
constrained to a closed set of non-sensitive labels, so a detection signature can never leak into a
log.

The engine depends on six injected **ports** — nothing is hard-wired, so it is trivially testable and
drags in no framework:

| Port | Provides | Typically bridges to |
|---|---|---|
| `EvaluatorInterface` | `classify()` + `synthesize()` | funnypot-core |
| `ReputationInterface` | an IP reputation verdict | funnypot-mainnet-client |
| `StateStoreInterface` | pins, blocklist, local mirror, rule state | host cache / DB |
| `GeoIpInterface` | country from a **local** GeoIP DB (no network) | host GeoIP DB |
| `Clock` / `Logger` | time + logging | host runtime |

## The cheapest-first ladder

`evaluate()` runs a fixed precedence and returns on the first gate that decides — the expensive
engine call happens **last**, and most requests never reach it:

1. **Allowlist** — self-IP / allowlisted IP·CIDR·ASN / safe-path. A hard override that beats everything below.
2. **Local pin / blocklist** — replay a pinned actor's exact prior treatment (deception consistency); a blocklist hit acts.
3. **Cheap static** — a sacrificial path (counterfactual-404) or an exact-match scanner tool UA, no engine call.
4. **Country gate** — an optional cheap-static check over the local GeoIP DB; by default a scrutiny *modifier*, not a lone block.
5. **Reputation** — mirror-first then cache-first (never a synchronous network call); a **modifier only**, never primary.
6. **Classify** — the engine's content verdict (the most expensive gate), combined with the axes above.

Then the posture/position **ceiling** caps the action, and the **learn-then-enforce** gate holds a
real-route rule to `log` until it has been promoted `SHADOW → TUNING → ENFORCED` (counterfactual-404
rules auto-enforce day-1).

## Invariants

- **Fail-safe to allow, never a 5xx.** Any port fault → `Decision::allow`.
- **Reputation is never primary.** Clean content is never blocked on reputation alone; the engine never deceives on reputation alone.
- **Deceive is fenced.** It survives only where the counterfactual is a 404, or on a real route past
  the block threshold via a *specific* matched signature — never the uncertainty band alone.
- **Status is app-chosen** (no model-driven 3xx), and every `reason` is a non-sensitive label (no
  signature strings in logs).

See [`docs/2026-08-19-funnypot-policy-design.md`](docs/2026-08-19-funnypot-policy-design.md) for the
full design.
