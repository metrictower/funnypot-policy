# metrictower/funnypot-policy · M (position-blind policy engine) — design spec

**Status:** draft for review · **Date:** 2026-08-19 · **Piece:** M of the funnypot-mainnet program (the program's 8th piece)
**Canonical:** [`funnypot-mainnet/docs/2026-08-19-program-decisions.md`](../../funnypot-mainnet/docs/2026-08-19-program-decisions.md) §M (wins over this spec on any conflict)
**Engine contract:** funnypot-core becomes the two-phase `classify()` + `synthesize()` engine (M2); this package holds it behind `EvaluatorInterface`
**Reputation source:** [`mainnet-client/docs/2026-08-19-mainnet-client-design.md`](../../mainnet-client/docs/2026-08-19-mainnet-client-design.md) (piece F — `ReputationGate`/`Client::check`, consumed here behind `ReputationInterface`)
**Consumers:** honeypot-wordpress (D), honeypot-laravel (E), the standalone app — each a THIN adapter (M's ripples)
**Prior art:** the user's production iCabbiTools suppression/scoring loop (the 4-layer model, aggregate-ban, TTL decay) is baked into §9

---

## 1. What this is + the mechanism/policy split

`metrictower/funnypot-policy` is the **decision brain** that sits between a host application and the
funnypot detection engine. It owns everything that is a *policy* question — POSITION, the
cheapest-first decision order, which action a band earns, learn-then-enforce promotion, pin/TTL
deception-consistency, and the reporting/suppression posture — and it owns **none** of the
*mechanism*: it never inspects request bytes to classify an attack, never renders a fake, never opens
a socket, never writes a store row, never emits a byte. It takes evidence in and returns a **`Decision`**
value object out (pure data, no side effects). The host adapter executes that `Decision`.

### The mechanism ↔ policy split (decision M2 + M3)

M splits the old monolithic "responder" along a clean seam:

| Concern | Owner | Shape |
|---|---|---|
| **Mechanism** — detect an attack, render a coherent fake | **funnypot-core** | `classify(request, SiteProfile) → Verdict` (cheap, content-only) + `synthesize(verdict, SiteProfile, seed) → FakeResponse` (only when told to deceive). Position-BLIND, action-FREE. |
| **Policy** — WHEN to classify, WHETHER to synthesize, what ACTION, WHERE (before/fallback), reporting | **funnypot-policy** (this package) | `evaluate(request-evidence) → Decision`. Position-AWARE, action-OWNING, side-effect-FREE (returns data). |
| **Execution** — normalize the request, run the `Decision`, persist, hook placement, admin UI | **the host adapter** (D/E/app) | Framework-specific glue. Thin. |

The engine is now a pair of pure-ish functions with no opinion about how it is used; this package is
the *only* place the opinions live; the host is the *only* place the side effects live. Three layers,
one responsibility each. This is what makes "honeypot vs WAF" and "before vs fallback" a **config
choice, never a code change** (M4): the same core + the same policy engine produce a classic honeypot
or a deceptive WAF purely from the operator's config array.

### Why a separate framework-free PHP >= 7.3 package

- **WordPress consumes it.** Piece D (honeypot-wordpress) runs on 7.x hosts. Like `mainnet-client`
  (F) and `funnypot-core`-after-C, this package is **PHP `>=7.3` from birth** and framework-free
  (PSR-4, no framework fingerprint — the same anti-fingerprint reason core has no framework). A
  framework dependency here would forbid the WP consumer or drag a fingerprint into the request path.
- **Policy is reusable across every posture and every host.** WordPress, Laravel, and the standalone
  app all need the identical decision matrix, the identical learn-then-enforce machine, and the
  identical suppression rules. Putting them in a shared package means one audited implementation of
  the security-critical precedence, not three drifting copies in three adapters.
- **It must not drag in the engine to make a cheap decision.** Most requests never reach
  `classify()` — they are resolved by allowlist, a local pin, a cheap-static check, or a cached
  reputation verdict (M5). The policy engine holds the engine behind an **interface** (`EvaluatorInterface`)
  so a deployment that only wants the cheap gates (an inline WAF that never deceives) can inject a
  no-op evaluator and never vendor nuclei-inversion. Same standalone rationale as F.
- **It is action-free and side-effect-free**, so it is trivially testable with fakes and cannot itself
  be the thing that reveals the honeypot or takes a site down (§10).

```
        ┌───────────────────────────────────────────────┐
        │ host adapter (D / E / app)                    │  framework glue, THIN
        │  normalize request → RequestEvidence          │
        │  execute Decision (block/deceive/log/allow)   │
        │  storage adapter, hook placement, admin UI    │
        └───────────────┬───────────────────────────────┘
                        │ evaluate(RequestEvidence) : Decision   (pure data)
                        ▼
        ┌───────────────────────────────────────────────┐
        │ funnypot-policy  (this package)  PHP >= 7.3   │
        │  PolicyEngine: cheapest-first precedence (M5) │
        │  learn-then-enforce state machine (M7)        │
        │  pin/TTL, suppression (§9)                     │
        │  ports: Evaluator / Reputation / StateStore / │
        │         GeoIp / Clock / Logger                │
        └───┬───────────────┬───────────────┬───────────┘
            │ Evaluator     │ Reputation    │ StateStore/GeoIp/Clock/Logger
            ▼               ▼               ▼
   funnypot-core     mainnet-client   host-backed
   classify()+       ReputationGate   (WP options / Laravel cache /
   synthesize()      (cache-first)     app SQLite; local GeoIP DB)
```

## 2. Ports + data inputs

The engine depends only on **interfaces** (ports); every side effect and every heavy dependency is
injected. All signatures are 7.3-legal (scalar/array/nullable param+return types; no promotion, enums,
`match`, `?->`, typed properties, or union types — value objects use untyped props + docblocks, per F).

### 2.1 `EvaluatorInterface` — holds the engine; decides WHEN to classify/synthesize

The engine seam. The policy engine calls `classify()` **last** in the precedence (it is the most
expensive gate) and calls `synthesize()` **only** when the policy has already chosen `deceive`.

```php
namespace Funnypot\Policy\Port;

interface EvaluatorInterface
{
    /**
     * Content-detection only (M2). Cheap, no I/O, no reputation, no position awareness.
     * Returns the engine's read of the request bytes against the declared stack.
     *
     * @param RequestEvidence $request   normalized request (method/path/query/headers/body-shape)
     * @param SiteProfile     $profile   declared stack + real-route oracle
     * @return Verdict   classification + matched signal + anomaly/severity
     */
    public function classify(RequestEvidence $request, SiteProfile $profile);

    /**
     * Render a coherent fake. Invoked ONLY when the policy chose action=deceive.
     * Owns nuclei-inversion / LLM / template fakes + STYLE. Deterministic in $seed so a
     * multi-step actor gets a coherent sequence from a stateless engine (M2).
     *
     * @param Verdict     $verdict  the verdict that justified deceiving
     * @param SiteProfile $profile
     * @param string      $seed     deterministic actor seed (§2.8)
     * @return FakeResponse   {status:int, headers:array, body:string, contentType:string}
     */
    public function synthesize(Verdict $verdict, SiteProfile $profile, string $seed);
}
```

`Verdict` (value object, mirrors core M2): `classification` (`clean | scanner-probe | attack-class |
suspicious`), `matched` (bool + an opaque signal handle — **never** a canonical signature string, §10),
`anomalyScore` (int, cumulative), `severity` (`low|medium|high`), `onRealRoute` (bool, resolved via
the `SiteProfile` oracle — did this path hit a route that actually exists?), and **`botSignals`** (the
decision-S request-shape signal set). The verdict is the **request-evidence axis** of §4.

**`botSignals` — the S request-shape bot-signal set (decision S1).** funnypot-core's `classify()` already
parses the request, so it computes the cheap request-shape heuristics there — empty/scanner/script User-Agent
class, missing `Accept`/`Accept-Language`/`Accept-Encoding`, absent `Sec-Fetch-*`/`Sec-CH-UA` fetch-metadata,
UA self-inconsistencies (claims Chromium but no client-hints; `Accept: text/html` with no `Accept-Language`),
and the digit-stripped + sorted-list **structural fingerprint** (header order/count — the JA4-H idea). These
ride the `Verdict` as a set of **opaque flags + a UA class + the fingerprint token** (`botSignals`), each with
core's starting weight already folded into `anomalyScore` (empty-UA +10, each missing header +5, a
self-inconsistency +10; scanner-UA decisive, script-UA a modifier — S1). It is **input-side only** — the flags
are never emitted, so they are fingerprint-safe (§10) — and core stays position-blind/action-free. The
**composite** decision on these signals is this package's job (§4), never core's; and per **S2** a single weak
signal never decides. Deliberately **NOT** an outdated-UA / version-age check (fragile + high-FP, S1) — the set
is header-PRESENCE + SELF-CONSISTENCY + the digit-stripped fingerprint, tolerant of old-but-legit clients.

`FakeResponse` is opaque to the policy engine — it flows back inside the `Decision` as a `fakeHandle`
(§3) for the adapter to emit; the policy engine never reads its bytes (it has no reason to, and reading
them would couple policy to mechanism).

### 2.2 `ReputationInterface` — the actor-evidence axis, cache-first

Wraps piece F's `ReputationGate`/`Client::check`. **The contract forbids a synchronous network call in
the request path** (M5 / decision N): an implementation returns only a **cached or fail-open** verdict
here — it consumes F's `cachedVerdict()` **and the local blacklist mirror** (O1, §2.3), never a live
socket. A fresh per-IP lookup, if the operator enabled checking, happens out-of-band (a warmer / the
report-drain tick) and populates F's cache; the request-path port reads that cache. The mirror is the
**primary fresh-read** (O1): most known-bad IPs are resolved from the synced thin blacklist artifact in
the `StateStore` with **zero** per-IP credit, and only an IP absent from the mirror escalates to the
per-IP cached verdict (still cache-first, never sync). A struggling/quota-exhausted mainnet trips F's
breaker (decision N) → the port returns a `fail-open` unknown, so uncertainty never blocks the request.

```php
namespace Funnypot\Policy\Port;

interface ReputationInterface
{
    /**
     * Cache-first reputation for an actor IP. MUST NOT make a synchronous network call on the
     * request path (M5) — return a cached verdict, or a fail-open 'unknown' when nothing is cached.
     * Inert (always 'unknown') unless the consumer enabled checking AND a key is set (F §4.1).
     *
     * @param string $ip
     * @return ReputationVerdict  {verdict: unknown|clean|suspicious|malicious|critical,
     *                             score: ?int, source: mirror|cache|fail-open|absent}
     */
    public function lookup(string $ip);
}
```

`ReputationVerdict` carries F's verdict enum + bounded score + a `source` marking whether it came from
the local blacklist mirror (O1), F's per-IP cache, or is a fail-open unknown, plus an optional **`usageType`**
(F's H1 `context.usage_type` — e.g. `datacenter`, surfaced so the policy can fuse "bot-UA + datacenter IP" per
**S3**). **Reputation is a modifier, never primary, and never sufficient to deceive** (§4) — this port only
reports; the precedence in §4 decides what it means.

**Signal telemetry rides the OUT-OF-BAND escalation check, never this request-path `lookup` (decision T).**
`lookup()` stays strictly read-only + cache/mirror-first (M5/N) and carries **no** signals. The S signal set
(§2.1 `botSignals`) travels instead on F's **out-of-band escalation check** for an uncertain (mirror-absent)
IP and on the **report** path — the policy collects the set from the `Verdict` and hands it to the adapter,
which attaches it to F's escalation-check + reporter calls as an opt-in `signals` object (§9 `ReportIntent`).
Check-carried signals are **low-trust observational telemetry** (T2): they enrich classification / calibration
(corroborate `usage_type=datacenter`, bot-likelihood) but **never** the abuse score and **never** a
request-path write (T3). Opt-in + disclosed (T4), gated by `bot_signals.telemetry` (§8).

**The mirror/gate matching rule (decisions P2 + Q2) — match by CONTAINMENT, never exact-match.** A
reputation entry's key (F's `score_key`) may be an IP (`/32` v4, `/128` v6), a **CIDR** (`/24` v4,
`/64` or `/48` v6), or an **ASN** (decision Q1). Both the local blacklist mirror (§2.3
`mirrorVerdict`) and the per-IP reputation lookup therefore resolve a visitor IP against entries by
**CIDR-containment / ASN-lookup**, **not** exact string match: a single `/24` row covers 256 addresses;
one ASN entry covers a whole network. A visitor IP is matched if any range/ASN entry *contains* it, so
the mirror stays small (block ranges, not many IPs — decision Q). Two rules on top:

- **IPv6 is normalised to its `/64` (or the entry's prefix) BEFORE lookup** (decision P2). Since the
  scored entity is the `/64` for IPv6 (G2), the client derives the visitor's `/64` `score_key` before
  a mirror-lookup and before a report — never a `/128` exact-match (which an attacker rotating `/128`s
  within a `/64` would trivially evade). A flagged coarser prefix (`/56`/`/48`, decision P4/Q1) is
  matched at that prefix.
- **Most-specific match wins** (decision Q4): an exact-IP verdict overrides its containing range for a
  check on that IP, and a range-allowlist entry (§8 `allowlist.cidrs`, the H2/K3 infra allowlist
  extended to ranges) exempts a known-good sub-range inside a listed range/ASN.

The `ReputationInterface` and `StateStoreInterface` mirror read are the *matching* seam; the entry data
(IP/CIDR/ASN rows) is supplied by F's mirror artifact + cache. The engine never enumerates ranges
itself — it asks the port "does anything cover this (normalised) IP?" and gets back a `ReputationVerdict`.

### 2.3 `StateStoreInterface` — pins, counters, rule state, suppression ledger

The one persistence seam. The host injects a backing (WP options/transients, Laravel `Cache`/DB, the
app's SQLite/file — the **same** injected store F uses). The engine only reads/writes through this
interface; it never touches a DB directly.

```php
namespace Funnypot\Policy\Port;

interface StateStoreInterface
{
    // --- deception-consistency pins + local blocklist (M5) ---
    public function getPin(string $ip);                              // ?Pin  {action, seed, expiresAt}
    public function setPin(string $ip, string $action, string $seed, int $ttlSeconds); // void
    public function isBlocked(string $ip);                           // bool  (local blocklist)

    // --- fleet-read: local blacklist mirror (O1) ---
    // The synced thin blacklist artifact (thin row {score_key, verdict, expires_at}; score_key is an
    // IP, a CIDR, or an ASN — P2/Q1). Pulled on cron via CDN + ETag/304, ~24 pulls/day. Cheap local
    // read; the PRIMARY fresh-read consulted before any per-IP reputation escalation (§4 step 4).
    // Matches the visitor IP by CIDR-CONTAINMENT / ASN-lookup, NOT exact-match (P2/Q2); the caller
    // normalises an IPv6 to its /64 (or the flagged prefix) before the lookup. Most-specific match
    // wins (Q4). Null => nothing covers the IP (escalate).
    public function mirrorVerdict(string $ip);                       // ?ReputationVerdict  (source='mirror')

    // --- learn-then-enforce per-rule state (M7) ---
    public function ruleState(string $ruleId);                       // RuleState {phase, since, count, exclusions[]}
    public function putRuleState(string $ruleId, RuleState $s);      // void
    public function bumpRuleEvaluated(string $ruleId, int $n = 1);   // void  (SHADOW req counter)

    // --- suppression ledger (§9) : verdict-dedup, per-IP cap, buffer-collapse, aggregate ---
    public function seenVerdict(string $dedupKey, int $ttlSeconds);  // bool  (true => already seen in window)
    public function incrAlertCount(string $ip, int $windowSeconds);  // int   (per-IP alerts this window)
    public function bufferReport(string $groupKey, array $report, int $ttlSeconds); // int (collapsed count)
    public function takeReportBuffer();                              // array (drain grouped reports)
    public function aggregateScore(string $scoreKey, int $windowDays); // AggScore {sources[], total}

    // --- rolling per-actor counters for the FP heuristic + velocity ---
    public function actorFacts(string $ip);                          // ActorFacts {authSession, loadsAssets, matches30d, firstSeen}
    public function incr(string $counterKey, int $windowSeconds);    // int
}
```

Everything stateful the engine needs is behind this one port. Reputation-caching is F's own store
(behind `ReputationInterface`), kept separate so the two concerns don't share a key namespace.

### 2.4 `Clock`

```php
namespace Funnypot\Policy\Port;

interface Clock { public function now(); }   // int epoch seconds
```

Injected so TTL/decay/window math is deterministic in tests (the state machine's "7 days AND 5,000
requests", the suppression windows, the TTL-decay scoring all read the clock, never `time()`).

### 2.5 `Logger`

```php
namespace Funnypot\Policy\Port;

interface Logger { public function log(string $level, string $message, array $context = []); } // void
```

PSR-3-shaped but **not** a `require` on `psr/log` (7.3 host, zero hard deps — same posture as F's
cache seam). The engine logs decisions and state transitions; it **never** logs a canonical signature
string, a raw attacker payload verbatim, or a secret (§10). A `NullLogger` ships as the default.

### 2.6 `GeoIpInterface` — country lookup from a LOCAL GeoIP DB (decision R2)

The country-resolution seam for the R country gate (§4 step 3a). **The contract forbids a network
call** (M5, same rule as reputation): country is resolved from a **local GeoIP DB** (the DB-IP Lite /
GeoLite2 dataset already used by the honeypot dashboard + A1 enrichment), never a remote lookup. The
host adapter provides the implementation over its shipped/refreshed local DB; a deployment that does
not want a country gate injects a `NullGeoIp` that always returns `null` (unknown), and the gate is a
no-op.

```php
namespace Funnypot\Policy\Port;

interface GeoIpInterface
{
    /**
     * ISO 3166-1 alpha-2 country code for an IP, from a LOCAL GeoIP DB. MUST NOT make a network
     * call (M5 / decision R2). Returns null when the DB has no answer (unknown country) — the gate
     * then falls through, never blocks on a lookup miss.
     *
     * @param string $ip   IPv4 or IPv6 (the DB resolves both — decision R2 note)
     * @return string|null two-letter country code, or null when unresolved
     */
    public function country(string $ip);
}
```

`GeoIpInterface` resolves **both IPv4 and IPv6** (DB-IP/MaxMind support it, decision R2). It reports a
country only; the *policy* on that country (deny-list / allow-list / modifier + the action) lives in
the config (§8) and is applied by the ladder (§4 step 3a), never in the adapter. A `NullGeoIp` (always
`null`) ships as the default so the gate is inert unless the operator configures country policy and the
adapter wires a real local DB.

### 2.7 `SiteProfile` — declared stack + real-route oracle (input data, not a port)

```php
namespace Funnypot\Policy;

final class SiteProfile
{
    // Declared stack: what the operator says this site IS (e.g. 'wordpress', 'laravel', 'static').
    // Drives which paths are sacrificial (a non-WP app: /wp-login.php provably doesn't exist).
    public function stack();                    // string
    // Real-route oracle: does this path resolve to a route that actually EXISTS on this site?
    // The single most important FP-safety input — a fake /wp-login.php must NEVER collide with a
    // real one (M2). The host supplies this (WP: is there a real handler? Laravel: does the router
    // match? app: is it a served file?).
    public function routeExists(string $path);  // bool
    // Sacrificial-path set for this stack (§6 day-1 carve-out): paths that provably don't exist here.
    public function isSacrificialPath(string $path); // bool
}
```

`SiteProfile` is **DATA that flows in**, not a service the engine calls out to — it makes the
position-blind engine *context-aware without being context-coupled* (M2). The `routeExists` oracle is
what keeps deception FP-free by construction (deceive only where the counterfactual is a 404, §5).

### 2.8 The deterministic seed

A stable per-actor seed (`sha1(actorId + siteSalt)` — actorId = the normalized source IP, or a
session/actor token when the adapter has one) flows into `synthesize()` so a **stateless** engine
produces a **coherent multi-step** fake: the same attacker probing `/admin` then `/admin/config` gets
responses that agree with each other, because both derive from the same seed. The seed is also pinned
in the `StateStore` (§2.3 `Pin.seed`) so a *later* request from a deceived actor re-uses the identical
seed → deception stays consistent across requests, not just within one (M5 deception-consistency).

## 3. The `Decision` output + the four actions

`evaluate()` returns exactly one `Decision` — **pure data, zero side effects** (M3). The adapter reads
it and performs the effect.

```php
namespace Funnypot\Policy;

final class Decision
{
    const ALLOW   = 'allow';    // pass to the real app, do nothing
    const LOG     = 'log';      // pass to the real app, but record/observe (shadow, or below-block)
    const BLOCK   = 'block';    // the adapter returns an honest refusal (e.g. 403) — protect-mode only
    const DECEIVE = 'deceive';  // the adapter emits the fakeHandle from synthesize()

    public function action();     // string, one of the four constants
    public function status();     // ?int   app-CHOSEN status (never model-chosen; no 3xx → no open redirect)
    public function fakeHandle();  // ?FakeResponse  present iff action === DECEIVE
    public function pinTtl();      // ?int   seconds to pin this actor's treatment for consistency (M5)
    public function report();      // ?ReportIntent  a suppression-shaped report the adapter may enqueue (§9), or null
    public function reason();      // string  a non-sensitive label for logging ('sacrificial-path','pin','reputation-modifier',...)
}
```

**The four actions v1 (M3 — challenge + tarpit CUT):**

- **`allow`** — not our traffic; hand to the real app. The default for the uncertainty band and for a
  clean verdict. Zero cost.
- **`log`** — hand to the real app **and** observe. This is the SHADOW-phase output (learn without
  acting, M7) and the "below block threshold but noteworthy" output. No visible effect on the response.
- **`block`** — an **honest** refusal (the adapter chooses the status, typically `403`). Only a
  **protect-mode** (WAF-posture / BEFORE-position) caller ever executes a block; a pure-honeypot
  deployment never emits one. A false-positive block is honest and self-correcting (M6).
- **`deceive`** — the adapter emits the `fakeHandle` (a `FakeResponse` from `synthesize()`). The classic
  honeypot upgrade of a 404, or a deceptive-WAF fake at the BEFORE position. **The status is
  app-chosen, never model-chosen** (M / security invariant 5) — no model-driven 3xx, no open-redirect;
  and the fake's Content-Type must match the request (invariant 5, enforced in core's synthesizer).

**Challenge and tarpit are deliberately absent from v1** (M3): a PHP-FPM tarpit is a self-DoS an
attacker triggers on purpose (it pins your worker, not theirs), and a challenge (JS/PoW interstitial)
is a v2 concern that needs a rendering surface the policy engine doesn't own. The `Decision` action
enum is closed at four; a future `challenge` is an additive constant, not a redesign.

## 4. Cheapest-first decision precedence (M5)

`PolicyEngine::evaluate()` runs a fixed, **cheapest-first** ladder and returns on the first gate that
decides. The ordering is not cosmetic — it is a cost gradient (a hash-set lookup before a network-shaped
concern before the expensive engine `classify()`), and it is the security-critical heart of the package.

```
evaluate(RequestEvidence e):
  1. ALLOWLIST            e.ip in allowlist / e.path in SAFE_PATHS  → Decision::allow  (HARD override;
                          beats reputation, beats everything below. FP backstop, §9)
  2. LOCAL PIN / BLOCKLIST
       store.getPin(e.ip) present   → replay the pinned action with the pinned seed  (deception
                                       consistency: a deceived actor keeps getting coherent fakes, M5)
       store.isBlocked(e.ip)        → Decision::block (protect-mode) / Decision::deceive (honeypot-mode)
  3. CHEAP STATIC        exact-match malicious-UA  OR  sacrificial-path (SiteProfile.isSacrificialPath)
                          → the posture's cheap-static action (deceive on a sacrificial path — its
                            counterfactual is a 404, so it is day-1 auto-enforced, §6). No engine call.
  3a. COUNTRY GATE       geo.country(e.ip) from the LOCAL GeoIP DB (§2.6) — a cheap-static gate (no
      (decision R)       network call, M5/R2), consulted AFTER allowlist/pin, BEFORE reputation/content.
                          Config is a country DENY-LIST (these countries are acted on) OR an ALLOW-LIST
                          posture (only these pass freely; others are acted on). On a match, the
                          configured action:
                            • score-modifier (DEFAULT) → raise scrutiny / arm the reputation-check
                              trigger + suppression; does NOT itself decide — falls through to step 4/5;
                            • deceive → the posture's deceive (honeypot-preferred over block, R3/M6);
                            • block → honest 403 (protect-mode; a tell, an explicit opt-in only, R3).
                          Hard block / allow-list posture is an explicit operator opt-in; the honeypot
                          posture prefers score/deceive over block (fingerprint-safety, M6). An unknown
                          country (geo miss / NullGeoIp) falls through — the gate never blocks on a miss.
                          Blunt-instrument FP caveat (VPN/CGNAT/roaming/cloud egress) is documented (R4).
  4. REPUTATION          MIRROR-FIRST, then CACHE-FIRST — NEVER a synchronous network call (M5 / N):
                          (a) store.mirrorVerdict(e.ip) — the synced local blacklist mirror (O1), a
                              cheap StateStore read that resolves known-bad IPs with ZERO per-IP credit;
                          (b) only for an IP ABSENT from the mirror ("uncertain") escalate to
                              rep.lookup(e.ip) — F's cache-first per-IP verdict, still never sync.
                          Both reads MATCH BY CIDR-CONTAINMENT / ASN-LOOKUP, not exact-match (P2/Q2):
                          an IPv6 is normalised to its /64 (or the flagged prefix) before lookup, and a
                          range/ASN entry covers every contained IP (most-specific match wins, Q4).
                          Either source is a MODIFIER ONLY (see the rules below): it can raise/lower
                          where the request-axis lands, extend a pin TTL, or gate reporting — it can
                          NEVER by itself produce block or deceive.
  5. ENGINE classify()   evaluator.classify(e, profile)  — LAST, the expensive gate. Produces the
                          request-evidence axis (Verdict), INCLUDING the S request-shape bot-signal set
                          (Verdict.botSignals, §2.1). Combined with the reputation modifier and the
                          per-rule learn-then-enforce phase (§6) to pick the final action. The bot-signals
                          are a COMPOSITE MODIFIER only (S2/S3, next section) — never a standalone gate.
  → default: Decision::allow  (nothing matched → not our traffic)
```

### The country gate (decision R)

Step 3a is a **cheap-static** country check — a local GeoIP lookup (§2.6), no network call (M5/R2) —
sitting after allowlist/pin and before the reputation and content gates. It gives an operator a geo
policy without touching code:

- **Two config shapes** (§8 `country`): a **deny-list** (named countries are acted on; everyone else
  passes) OR an **allow-list posture** (only named countries pass freely; everyone else is acted on). An
  allow-list is the **infra allowlist extended to geo** (H2/K3) — a listed country still gets full
  content detection downstream, it just skips country-scrutiny; it is *not* a blanket pass.
- **Action is configurable, DEFAULT = score-modifier** (R3). As a modifier the gate does not decide —
  it raises scrutiny and **arms the reputation-check trigger + suppression scoring**, then falls through
  to steps 4/5. `deceive` and `block` are the other two actions; **hard block or the allow-list posture
  is an explicit operator opt-in**, and in the **honeypot posture prefer score/deceive over block**
  because a country block is a tell and deceiving a wrongly-flagged legit user is silent corruption
  (M6). A geo miss (unknown country / `NullGeoIp`) always falls through — the gate never blocks on a
  lookup miss.
- **Blunt-instrument FP caveat (R4):** country attribution is coarse (VPN/CGNAT/roaming/cloud egress mis-
  locate legitimate users), so the gate is an eyes-open opt-in; the allow-list posture is stricter and
  higher-FP than a deny-list. This is exactly why the default action is a *modifier*, not a block.

### The two-axis combination (M5)

Every non-trivial decision combines **two independent axes**:

- **Actor evidence** = reputation (who is asking) — the local blacklist mirror first, then F's per-IP
  cache (step 4). Both are cache/mirror reads, never a request-path network call (M5 / N).
- **Request evidence** = content (what they are asking for) — from `classify()`, step 5.

They are combined into the final action, but under three **hard rules** that keep reputation in its
lane:

1. **Reputation is a modifier, never primary.** The request axis is what can escalate to `block`/
   `deceive`. Reputation can only *modify* the request-axis outcome — tighten a threshold, lengthen a
   pin, promote a "log" to a "block" on an *already-content-suspicious* request, or gate whether a
   report fires. It is a tiebreaker on the margin, never the headline.
2. **Never deceive on reputation alone.** A bad IP asking for a legitimate, existing route is **not**
   deceived — deception requires a request-evidence signal (a specific matched signature or a
   sacrificial path), because deceiving a real route is silent corruption (§5). A bad IP with no
   request signal at most gets `block` (protect-mode) or `log`, never `deceive`.
3. **Never block on reputation alone by default.** Under the default posture, reputation raises
   suspicion and feeds suppression/scoring, but a lone `malicious` verdict on an innocuous request
   maps to `log`, not `block`. Only an operator who explicitly opts into "reputation-block" (F's
   `block_verdicts`, surfaced as a posture knob) turns an extreme reputation verdict into a `block` —
   and even then only at the BEFORE position, never a deceive.

This is the discipline that prevents the two classic failure modes: deceiving a legitimate user
because their CGNAT neighbor was bad (rule 2), and blocking a whole shared egress on one stale verdict
(rule 3). The allowlist at step 1 is the final backstop under all of it.

### Request-shape bot-signals as composite modifiers (decisions S2 / S3 / S5)

The S request-shape signals (`Verdict.botSignals`, computed in core's `classify()`, §2.1) are the third
strand woven into the **request-evidence axis** — and they obey the same "modifier, never primary"
discipline as reputation:

- **Composite only — a single weak signal never decides (S2 / M6).** No lone bot-signal — not an empty
  User-Agent, not a missing `Accept-Language`, not an absent `Sec-Fetch-*` — ever produces `block` or
  `deceive` on its own. Each signal's weight (already folded into `Verdict.anomalyScore` by core, S1)
  **accumulates** into the anomaly/suspicion total; a scanner-UA (nmap/sqlmap/nuclei/…) is decisive on its
  own only because it is an unambiguous tool signature, not a weak heuristic. A cumulative bot-signal
  anomaly with no specific matched signature stays in the uncertainty band — it reaches at most `log` (or
  `block` in a strict protect-mode), **never** `deceive` (§5).
- **Fusion across the two axes (S3).** The composite is where **"bot-UA + datacenter IP" combines**: the
  policy fuses core's `Verdict` (request-shape + content) × reputation (the step-4 verdict **and its
  `usageType`** — e.g. `context.usage_type=datacenter`, §2.2) × the country modifier (R, step 3a). A bot-shape
  request from a datacenter range, or from a scrutinised country, is more suspicious than either alone; the
  three modifiers add, they do not each independently gate.
- **Where the signal-anomaly enters the ladder.** Like the country modifier (step 3a), the bot-signal
  composite is **not itself a returning gate** — it **raises scrutiny**: it tightens the request-axis
  threshold, **arms the reputation-check escalation trigger** (an uncertain, mirror-absent IP with a bot-shape
  request is a stronger candidate for F's out-of-band escalation check, O1/T), and feeds the suppression
  scoring (§9). It modifies where the two-axis combination lands; the final action is still chosen by §4's
  rules + the §5 ladder.
- **FP guards apply FIRST (S5 — critical).** Before **any** browser-shape signal is counted, the policy
  applies the false-positive carve-outs: the step-1 **allowlist** (ips/cidrs/asns) + **SAFE_PATHS**, plus the
  **SAFE-UA / exemption set** for legitimately header-light clients (monitoring, API, server-to-server, feed
  readers) and non-browser paths (`.map` source-map fetches). An exempt actor's bot-signals are **zeroed, not
  counted** — a legit no-header client is **carved out specifically**, not globally leniently scored (which
  would blind the signal for real bots). This ordering is why "missing browser headers" can be a signal at all
  without punishing every curl-based health check. The exemption set is config (§8 `bot_signals`), and the
  allowlist-everywhere backstop (§9) re-checks it at every mutating point.

## 5. The deception governing rule (M6)

One review-enforceable sentence:

> **Deceive where the counterfactual is a 404; above the block threshold on real routes; never in the
> uncertainty band.**

Operationally:

- **Counterfactual-404 paths** (sacrificial paths, unrouted probe paths — `SiteProfile.routeExists`
  is false): deception is **FP-free by construction**. There is no legitimate user of `/.env` on a
  site that has no `/.env`; the honest alternative was a 404; a fake is strictly a better 404. These
  can auto-enforce on day one (§6).
- **Real routes** (`routeExists` true): the ladder is **`allow → log → block → deceive`**, and
  `deceive` sits **above** `block`. Deception on a real route is only reached by a **specific matched
  signature** that is already past the block threshold — an unambiguous attack payload aimed at a
  route that exists. A cumulative anomaly score **alone** can never reach deceive (it can reach `log`,
  and, in protect-mode, `block`).
- **The uncertainty band: never deceive.** If the engine is merely suspicious — anomaly accumulating,
  no specific signature — the answer is `log` (or `block` in a strict protect-mode), **never**
  `deceive`.

The rationale is asymmetric cost, and it is the reason challenge/tarpit were cut and deceive was
fenced this tightly: **a false-positive `block` (a 403) is honest and self-correcting** — the user
sees an error, retries, or contacts support, and no data is silently lost. **A false-positive
`deceive` is silent corruption** — the worst case is a deceived `POST`: a legitimate user's form
"succeeds" against a fake, they believe their data was saved, and it is silently gone. Therefore:
**deception is the payoff for CERTAINTY, not a hedge for uncertainty.** Certainty (a specific
signature, or a provably-nonexistent path) earns deception; uncertainty earns at most an honest block.

## 6. Learn-then-enforce state machine (M7)

Per-**rule** promotion, **asymmetric**: promotion is human-gated and slow; demotion is automatic and
instant. A rule is a single detection signal (an engine matcher class, a cheap-static check, a
sacrificial-path pattern). State lives in `StateStore.ruleState(ruleId)`.

```
        ┌─────────┐   min 7 days AND ≥5,000 evaluated requests
        │ SHADOW  │   (log-only; action forced to LOG regardless of what the rule "wanted")
        └────┬────┘
             │ dwell + volume satisfied
             ▼
        ┌─────────┐   compile SCOPED exclusion tuples (rule_id, path_prefix, param) — never a global
        │ TUNING  │   disable. FP heuristic flags a match on an otherwise-legit actor; a HUMAN approves.
        └────┬────┘
             │ human approve  +  zero suspected FPs in the window
             ▼
        ┌─────────┐   per-rule, ONE click. The rule's action now applies for real.
        │ ENFORCED│
        └────┬────┘
             │ hits a subsequently-PROVEN-legit actor  → AUTO-DEMOTE to SHADOW + ALERT
             ▼        (plus a global kill-switch flips every rule to SHADOW at once)
        (back to SHADOW)
```

- **SHADOW** — the rule runs and logs, but its action is forced to `log`; it affects nothing visible.
  Entry gate to leave: **min 7 days AND min 5,000 evaluated requests** (both — a low-traffic site
  needs the calendar time; a high-traffic site needs the volume). `StateStore.bumpRuleEvaluated`
  counts; `Clock` provides the dwell.
- **TUNING** — the engine compiles **scoped exclusion tuples** `(rule_id, path_prefix, param)` from an
  **FP heuristic**: the rule matched an actor who is *otherwise legit* — an authenticated session, a
  clean reputation, loads page assets, and has **no other rule matches in 30 days** (all read from
  `StateStore.actorFacts`). A flagged pattern becomes a **scoped exclusion** (never a global disable —
  a global disable throws away the rule's value everywhere to fix one path). A **human approves** each
  promotion. A **baseline of known-FP-prone rules ships pre-excluded** (the paranoia-level-1 analog —
  the rules that are notorious for firing on legitimate rich-text/URL params start life excluded).
- **ENFORCED** — per-rule, one click, only after **zero suspected FPs in the window**. The rule's
  intended action (block/deceive per the posture and §5) now applies.
- **Auto-demote (automatic, instant).** Any ENFORCED rule that fires on an actor **subsequently proven
  legit** (they later authenticated, or the reputation resolved clean, or an operator whitelisted them)
  **demotes to SHADOW and raises an alert**. Demotion never waits for a human — the asymmetry is the
  safety property (a wrong enforce is expensive; reverting it must be free and immediate). A **global
  kill-switch** demotes every rule to SHADOW at once for an incident.

### DAY-1 sacrificial-path auto-enforce carve-out (M7)

The one exception to "everything starts in SHADOW": the **sacrificial-path set** (paths that provably
don't exist on this site — `.env`, `.git/config`, `/wp-login.php` on a non-WP app, resolved via
`SiteProfile.isSacrificialPath` + `routeExists=false`). These **auto-enforce on install day**, because
their counterfactual is a 404 → the FP cost is **zero by construction** (§5), and they are **most of
the real attack volume**. This delivers value on install day while every *risky* (real-route) rule is
still safely in shadow learning. The carve-out is scoped precisely to counterfactual-404 rules; no
real-route rule ever skips SHADOW.

## 7. Default install posture (M8)

On a fresh install, with no operator tuning:

- **FALLBACK position deceives everything.** At the 404 fallback, every unmatched request is deceived —
  this is **FP-free by construction** (a request that reached the 404 fallback had no real route, so
  the counterfactual is a 404, §5). The classic honeypot behavior works on install day with zero
  tuning and zero FP risk.
- **BEFORE position runs only the FP-free-by-construction gates immediately**, everything else in
  SHADOW:
  - sacrificial-path deception (day-1 carve-out, §6),
  - local blocklist (explicit operator/pinned bad actors),
  - extreme-reputation block **only if the operator opted into reputation-block** (off by default,
    §4 rule 3),
  - **every real-route detection rule starts in SHADOW** (§6) — learning, not acting.

So a default install is a working honeypot at the fallback (safe, valuable immediately) and a
*learning* WAF at the before-position (acting only where FP cost is provably zero). The operator
promotes real-route rules to ENFORCED deliberately, one click at a time, after the shadow window.

## 8. Postures + the operator config array

### Postures as config presets (M1/M4)

**POSTURE** (`honeypot | WAF | both`) is what the operator wants the deployment to BE — a **preset
bundle of policy defaults**, orthogonal to **STYLE** (`minimal|realistic|taunt`, which is how a fake
*looks* and stays entirely in core's `synthesize()`).

| Posture | Position default | Real-route action ceiling | Reputation-block | Notes |
|---|---|---|---|---|
| `honeypot` | FALLBACK | `deceive` (at fallback) / `log` before | off | classic: upgrade every 404 to a fake; observe before |
| `WAF` | BEFORE | `block` | opt-in | classic protect: honest 403 on enforced rules; no deceive on real routes unless a specific signature clears §5 |
| `both` | BEFORE **and** FALLBACK | `block` before, `deceive` at fallback | opt-in | a single install can block/deceive at the before-position **and** deceive at the 404 fallback (M4) |

The four position×action combos (M4) — deceive-AFTER (honeypot), deceive-BEFORE (deceptive WAF),
block-BEFORE (WAF), block-AFTER (rare) — all fall out of these two knobs; no combo needs new code.

### The config array (serializable; WP admin and Laravel config produce the SAME array)

Config is **plain serializable data** (M3) — a nested assoc array. A WordPress admin screen and a
Laravel config file are two front-ends that emit the identical structure; the engine reads only the
array (built via `PolicyConfig::fromArray()`, the F-style `fromArray` builder — 7.3 has no named args,
M15).

```php
[
  'posture'  => 'honeypot',            // honeypot | WAF | both  (preset selector)
  'position' => ['fallback' => true, 'before' => false],  // overridable per posture (M4 knobs)

  // per-band action ceiling on REAL routes (the §5 ladder). Sacrificial/404-counterfactual paths
  // are governed separately by the day-1 carve-out and always may deceive.
  'actions' => [
    'clean'         => 'allow',
    'suspicious'    => 'log',          // uncertainty band → never deceive (§5)
    'attack_class'  => 'block',        // specific class, real route → block (deceive only on a specific signature past threshold)
    'scanner_probe' => 'deceive',      // counterfactual 404 → deceive
  ],

  'reputation' => [
    'enabled'        => false,         // opt-in (F check gate) — off by default
    'block_verdicts' => ['malicious','critical'],  // ONLY consulted as a MODIFIER (§4 rules); block-on-rep is opt-in
    'min_block_score'=> null,
    'as_primary'     => false,         // HARD false by default — reputation is never primary (§4)
  ],

  'learn' => [
    'shadow_days'      => 7,
    'shadow_min_reqs'  => 5000,
    'baseline_excluded'=> [ /* known-FP-prone rule ids, pre-excluded (§6) */ ],
    'kill_switch'      => false,       // flip true to demote every rule to SHADOW
  ],

  'country' => [                       // decision R — the §4 step 3a cheap-static country gate (local GeoIP, R2)
    'enabled'   => false,              // off by default — an eyes-open opt-in (blunt instrument, R4)
    'mode'      => 'deny',             // 'deny' (deny-list) | 'allow' (allow-list posture; stricter/higher-FP, R4)
    'countries' => [],                 // ISO 3166-1 alpha-2 codes acted on (deny) / passed freely (allow)
    'action'    => 'modifier',         // DEFAULT 'modifier' (raise scrutiny + arm the reputation trigger) |
                                       // 'deceive' | 'block'. Hard block / allow-list = explicit opt-in;
                                       // honeypot posture prefers score/deceive over block (R3/M6).
  ],

  'bot_signals' => [                   // decision S/T — request-shape weak signals: core computes (S1), policy fuses (S3)
    'enabled'      => true,            // fuse core's Verdict.botSignals as a COMPOSITE modifier (S2/S3); false = ignore them
    'exempt_uas'   => [],              // SAFE-UA set — monitoring/API/server-to-server/feed-reader agents, carved out FIRST (S5)
    'exempt_paths' => [],              // e.g. '*.map' source-map fetches — non-browser-legit paths carved out FIRST (S5)
    'telemetry'    => false,           // decision T — opt-in + disclosed (T4): attach the signal set to F's out-of-band
                                       // escalation check + the report (T1); low-trust, never the abuse score (T2/T3).
  ],                                   // per-signal WEIGHTS live in core.classify() (S1) — referenced, not duplicated here.

  'pin' => [ 'ttl_seconds' => 3600 ],  // deception-consistency pin lifetime (M5)

  'suppression' => [                   // §9 — the iCabbiTools 4-layer prior-art model
    'verdict_dedup_hours'  => 24,
    'per_ip_alert_cap'     => 100,
    'per_ip_cap_window_s'  => 600,
    'buffer_ttl_s'         => 900,
    'score_gate'           => 200,     // only alert above this score
    'aggregate' => [ 'min_sources' => 2, 'min_total_score' => 200, 'window_days' => 90 ],
    'decay' => [ 'base_ttl_s' => 600, 'cap_ttl_s' => 86400,
                 'inc_soft' => 1, 'inc_medium' => 10, 'inc_hard' => 100 ],  // hard-tell = instant
  ],

  'allowlist' => [ 'ips' => [], 'cidrs' => [], 'asns' => [], 'safe_paths' => [ /* isIgnoredUri set */ ] ],
                                       // ips/cidrs/asns matched by CONTAINMENT (P2/Q2/Q4): a known-good
                                       // /24 inside a listed bad ASN is exempt (range allowlist = infra
                                       // allowlist extended to ranges, H2/K3).
  'self_ips'  => [],                   // operator's own egress — never self-score/self-report
]
```

Every value is a scalar/array — JSON/PHP-serializable, so the exact same array round-trips through a
WP option, a Laravel `config('funnypot.policy')`, or the app's env-derived config. Choosing honeypot
vs WAF and before vs fallback is picking values in this array — **never a code change** (M4).

## 9. Report suppression + scoring (the iCabbiTools prior-art model)

The policy engine emits a `ReportIntent` on the `Decision` when a report is warranted; the adapter
enqueues it (to mainnet via F's reporter, and/or the operator's alert channel). Before an intent is
emitted, it passes the **4-layer suppression model** validated in the user's production iCabbiTools
loop, plus the aggregate-ban rule, plus the allowlist/SAFE_PATHS/OAST backstops.

**The 4 suppression layers (all keyed through `StateStore`):**

1. **24h verdict-dedup** — key `sha1(ip + result + source)`; `StateStore.seenVerdict(key, 24h)`. The
   identical verdict about the identical actor from the identical source is reported **once per 24h**.
2. **Per-IP alert cap** — **100 alerts per 600s** per IP (`StateStore.incrAlertCount`); a noisy single
   actor cannot flood the operator's channel.
3. **Buffer-and-collapse** — TTL ~**900s**: reports for a group are buffered and **collapsed into one
   message**, repeats rendered as `(×N)` (`StateStore.bufferReport` / `takeReportBuffer`), so a burst
   becomes one line, not a hundred.
4. **Score-gated** — an alert only fires when the actor's decayed score clears the **score gate**
   (default 200). Below the gate, the event is recorded but not alerted.

**TTL-based scoring decay** feeds the gate: base TTL 600s, cap 86,400s; increments **+1 soft / +10
medium / +100 hard-tell** (a hard tell — an unambiguous exploit signature — is effectively instant).
Score is a decayed accumulator (the same read-time-decay shape as the mainnet G1 model), so it drifts
down without a sweep.

**Aggregate-ban rule** — an actor is escalated to a ban recommendation only with **≥2 distinct sources
AND total_score ≥ 200 over a 90-day window** (`StateStore.aggregateScore`). This mirrors the mainnet
≥2-distinct-source listing gate (D4) — a lone source can never manufacture a ban.

**Bot-signal report evidence + the `signals` telemetry object (decisions S4 / T).** When a bot-shape actor
warrants a report, the `ReportIntent` carries a **`bad-bot`-class category** with a **signal-weighted
confidence** (S4) — the composite bot-signal weight scales the reported confidence, subject to the same
suppression/quorum as any report (a lone source still cannot list an IP, D4). Separately, when
`bot_signals.telemetry` is enabled (opt-in + disclosed, T4), the intent carries an optional **`signals`**
object — the S bot-signal set (missing-header flags, self-consistency flags, UA class, the digit-stripped
structural fingerprint) + the local anomaly summary (T5). The adapter attaches the identical `signals` object
to F's **out-of-band escalation check** so mainnet gathers telemetry even when the check returns safe/unknown
(T1) — but that path is **low-trust** (T2), **async**, and **never a request-path write** (T3). The `signals`
object is fingerprint-safe: flags/classes/tokens only, **never** a raw payload or a canonical signature string
(§10).

**Backstops checked at EVERY mutating point (the FP safety net):**

- **Allowlist-everywhere** — the allowlist is re-checked at **every** point that would score, report,
  pin, or block — not just at the top of `evaluate()`. An allowlisted actor can never be scored or
  reported even if a downstream layer would have (defense in depth, the FP backstop).
- **SAFE_PATHS / `isIgnoredUri`** — operator-and-app-generated traffic (health checks, the admin UI's
  own requests, asset paths) is on a never-self-score/never-self-report list. The honeypot must never
  report itself.
- **`self_ips`** — the operator's own egress IP is never scored or reported (mirrors the app's
  `FUNNYPOT_SELF_IPS` invariant — test traffic must never report an innocent IP).
- **OAST hygiene** — attacker payloads frequently embed OAST/callback URL-shaped paths (an
  interactsh-style domain, a `//evil.example/x` path). These are **never forwarded verbatim** into
  logs, alerts, or any DNS-resolving sink — the engine records a redacted shape, never the live
  attacker-controlled URL, so the honeypot can't be turned into an SSRF/beacon amplifier for the
  attacker.

## 10. Security + fingerprint-safety

- **The engine never acts, so it can't reveal.** funnypot-policy returns a `Decision` (data) and
  emits no bytes, opens no socket, writes no store row directly. A pure honeypot deployment never
  produces a `block` at all; only a **protect-mode** caller (WAF-posture / BEFORE) ever executes a
  block, and a block is an honest 403, not a tell. The one behavior that *could* reveal — a fake — is
  produced by core's `synthesize()`, whose output must match the request Content-Type and carry an
  app-chosen status (invariant 5). The policy engine only decides *whether* to deceive, never *how the
  fake looks*.
- **Fingerprint-safety by delegation (invariant 1).** The `Verdict.matched` signal is an **opaque
  handle**, never a canonical signature string. The policy engine never sees, stores, logs, or emits a
  nuclei matcher word, a CRS rule id / `msg`, or a ModSecurity/OWASP_CRS marker — those live only
  inside core's compiled artifacts behind the classify() seam and are gated by core's CI. `Logger`
  output and `Decision.reason` are constrained to non-sensitive labels (`'sacrificial-path'`,
  `'pin'`, `'reputation-modifier'`), never a raw payload or a signature. The engine cannot leak a
  fingerprint it is never given.
- **Deception consistency via pin/TTL (M5).** A deceived actor is pinned (`StateStore.setPin` with the
  actor seed and a TTL) so every subsequent request replays the **same** action with the **same** seed
  → the fakes stay mutually coherent. An attacker probing for inconsistency (the classic honeypot
  unmask — "the same path returned two different fakes") sees a stable, self-consistent site.
- **Never deceive/block on reputation alone; deceive only where the counterfactual is a 404** (§4, §5)
  — the two rules that keep a false positive from becoming silent corruption or a shared-egress
  outage.
- **No RCE surface.** Unlike the rules-updater, this package only reads request evidence and returns
  data; it never `require`s or executes anything derived from a request. The config array comes from
  operator config, never from attacker-controlled data.
- **Fail-safe under the LLM invariant (2).** **Every** port fault degrades to `Decision::allow` (or, at
  the fallback position, a plain 404) — an evaluator/synthesize throw, a **reputation throw**, a **store
  throw**, a **geoip throw**, a logger throw, a clock throw — never a 500, never an uncaught throw on the
  request path.
  `evaluate()` **never** throws. The store is hit on **every** request (precedence step 2, the pin/mirror
  read), so a cache/store outage is the most likely throw site — it must fail open like the rest. A policy
  fault can only ever *fail open to the real app*, matching the honeypot's "the LLM only ever upgrades a
  404" rule.

## 11. Testing strategy

Pure PHPUnit, host-run, **no network, no DB** — every port is a fake. The security-critical logic (the
precedence, the ladder, the state machine, suppression) is exhaustively table-tested.

- **Fakes for every port:** `FakeEvaluator` (scripts a `Verdict` for a request and records whether
  `synthesize` was called — proves synthesize runs **only** on `deceive`), `FakeReputation` (scripts a
  cached verdict + asserts `lookup` never blocks / makes no call), `ArrayStateStore` (in-memory pins,
  counters, rule state, suppression ledger, **the CIDR-containment/ASN mirror**), `FakeGeoIp` (scripts an
  IP→country map + asserts `country` makes no network call, returns null on a miss), `FixedClock` (drives
  dwell/TTL/decay deterministically), `RecordingLogger` (asserts no signature string / raw payload / secret
  ever appears).
- **Decision matrix (§4):** a table over (reputation verdict × request verdict × posture × position) →
  assert the exact `Decision.action`. Explicitly assert the three reputation rules: a bad IP on a real
  existing route is **never** deceived (rule 2); a lone `malicious` on an innocuous request maps to
  `log`, not `block`, under default (rule 3); reputation only *modifies* an already-content-suspicious
  outcome (rule 1). Assert allowlist at step 1 overrides a `malicious` reputation. Assert the **mirror
  is consulted before the per-IP lookup** (O1): an IP present in `store.mirrorVerdict` resolves from the
  mirror and `ReputationInterface.lookup` is **never** called; only a mirror-absent ("uncertain") IP
  escalates to the cache-first `lookup`, which still makes no network-shaped call. Assert the **mirror +
  reputation match by CIDR-containment / ASN-lookup** (P2/Q2): an IP inside a seeded `/24` or under a
  seeded ASN row matches; an IPv6 `/128` inside a seeded `/64` matches after normalisation; an exact-IP
  row beats its containing range (Q4).
- **Country gate (§4 step 3a, decision R):** a table over (mode deny/allow × action modifier/deceive/block
  × posture). Assert the **default `modifier` falls through** (arms scrutiny, does not itself return);
  `block` is reached only on an explicit opt-in; the **allow-list posture** acts on non-listed countries
  and passes listed ones; a **geo miss** (`FakeGeoIp` → null / `NullGeoIp`) falls through and never blocks;
  a disabled gate never calls `geo.country`; `country` makes **no network call**.
- **Request-shape bot-signals (§4 composite, decisions S2/S3/S5):** a table over (bot-signal set × reputation
  `usageType` × country modifier × posture). Assert a **single** weak signal never `block`s/`deceive`s (S2) —
  it only raises the anomaly/scrutiny; assert the composite **fuses** with `usageType=datacenter` and the
  country modifier (S3 — "bot-UA + datacenter IP" escalates where either alone would not); assert an
  anomaly-score-only bot-shape (no specific matched signature) reaches at most `log` (never `deceive`, §5);
  assert the **FP guards apply FIRST** (S5) — an `exempt_uas`/`exempt_paths`/allowlisted actor's bot-signals
  are **zeroed, not counted** (a header-light monitoring/API/feed client is carved out, a `.map` fetch
  exempt), while a non-exempt no-header client still accrues the signal; assert `bot_signals.enabled=false`
  ignores the set entirely.
- **Signal telemetry (decision T):** assert the request-path `ReputationInterface.lookup` carries **no**
  signals and makes no write (T3); assert the `ReportIntent` carries a `bad-bot` category with signal-weighted
  confidence (S4) and, **only** when `bot_signals.telemetry=true`, the opt-in `signals` object (T4/T5); assert
  the `signals` object is fingerprint-safe (`RecordingLogger`/intent inspection finds flags/classes only,
  never a raw payload or signature string, §10).
- **Deception governing rule (§5):** assert deceive is reachable on a counterfactual-404 path and on a
  specific signature past threshold on a real route; assert deceive is **never** returned in the
  uncertainty band (anomaly-score-only) — that path yields `log`/`block`.
- **State-machine transitions (§6):** SHADOW forces `log` regardless of the rule's wanted action;
  promotion needs **both** 7 days (via `FixedClock`) AND 5,000 requests (via `bumpRuleEvaluated`) —
  assert neither alone promotes; TUNING compiles a **scoped** exclusion tuple (never a global disable);
  a human-approve step is required before ENFORCED; an ENFORCED rule hitting a proven-legit actor
  **auto-demotes to SHADOW and alerts** without a human; the global kill-switch demotes all rules.
- **Day-1 sacrificial-path enforce (§6/§7):** on a fresh config (all real-route rules in SHADOW),
  assert a sacrificial path (`SiteProfile.isSacrificialPath` true, `routeExists` false) is
  **immediately** deceived, while a real-route attack-class rule is only `log`ged (still shadow).
- **Suppression dedup (§9):** assert the 24h verdict-dedup emits one intent per `sha1(ip+result+source)`
  per window; the per-IP cap stops at 100/600s; buffer-and-collapse renders `(×N)`; the score gate
  suppresses below 200; the aggregate rule needs ≥2 distinct sources AND ≥200 over 90d. Assert
  allowlist/`self_ips`/SAFE_PATHS suppress a report at every mutating point, and an OAST-shaped path is
  never emitted verbatim.
- **Fail-safe (every port):** a throw from **any** port → `evaluate` still returns `Decision::allow`
  (never propagates, never 500s). Cover each throw site, not just the evaluator: an evaluator/synthesize
  throw, a **store throw** (the highest-probability site — the store is read on every request at
  precedence step 2), a **reputation throw**, a **geoip throw** (the step-3a country lookup), and a
  logger/clock throw all degrade to `allow`.
- **7.3 lane:** the package runs its **own** 7.3 CI (its own matrix, like F) — lint + run the suite on
  a 7.3 interpreter so no 7.4+ construct slips in.

## 12. Dependencies + what MUST stay per-integration

### Dependencies

- **funnypot-core (the two-phase engine contract, M2/M's ripple).** This package requires core's
  `classify()` + `synthesize()` split behind `EvaluatorInterface`. Core's ripple: split the responder
  into the two phases, add the `SiteProfile` + `seed` inputs, stay position-blind/action-free, and
  **compute the S request-shape bot-signal set** (the digit-stripped structural fingerprint + presence/
  self-consistency flags + UA class) into `Verdict.botSignals` + `anomalyScore` (decision S1) — input-side
  only, never emitted (fingerprint-safe). The deception **content** is fully retained — it moves under
  `synthesize()`, nothing is lost. This is the one interface change that touches all core consumers.
- **mainnet-client (F) via `ReputationInterface`.** Reputation is consumed behind the port, cache-first,
  never a synchronous request-path call (M5 / decision N). F is unaffected structurally; the policy engine
  is a new consumer of its `ReputationGate`/cache. The **primary fresh-read is the local blacklist mirror**
  (O1): the host adapter pulls the thin blacklist artifact on cron (CDN + ETag/304, ~24 pulls/day) into
  the `StateStore`; the engine reads `store.mirrorVerdict()` before escalating an uncertain IP to F's
  per-IP cached verdict — so fleet growth is CDN egress, not origin QPS. The earlier "reputation-block
  feature" (F's D/E ripple) **becomes policy actions** here — block-on-reputation is now the opt-in
  modifier of §4, not a standalone gate. **Signal telemetry (decision T):** the policy collects the S
  `botSignals` set from the `Verdict` and hands it to the adapter, which attaches it (opt-in,
  `bot_signals.telemetry`) as F's `signals` object on the **out-of-band escalation check + the reporter
  call** — never on the request-path `lookup` (T3). F's ripple: accept a `signals` object on check + report;
  A1 async-queues it as low-trust enrichment/calibration telemetry, never a read-path write and never the
  abuse score (T2/T3).
- **Zero framework deps, zero hard PSR deps** (7.3 host) — `Logger`/`Clock`/`GeoIp`/cache-shaped seams
  are defined locally with shipped no-op defaults (`NullLogger`, `NullGeoIp`), exactly like F's `Cache`
  seam. The country gate is inert until the adapter injects a real `GeoIpInterface` over a local DB.

### What MUST stay per-integration (the THIN adapter — D/E/app)

The policy engine is deliberately incomplete without a host adapter. Each integration keeps, and only
keeps:

1. **Request normalization** — turn the framework's request (WP `$_SERVER`, a Laravel `Request`, the
   app's PSR-7) into the neutral `RequestEvidence` + build the `SiteProfile` (declared stack + the
   real-route oracle — WP: is there a real handler? Laravel: does the router match? app: is it a served
   file?). This is the one piece only the host can do, because only the host knows its own routes.
2. **`Decision` execution** — perform the effect: `allow`/`log` → hand to the real app (+ observe);
   `block` → emit the honest 403; `deceive` → emit the `fakeHandle`. Status is taken from the
   `Decision`, never invented (invariant 5).
3. **Storage adapter** — implement `StateStoreInterface` over the host's store (WP options/transients,
   Laravel cache/DB, the app's SQLite/file) — the **same** injected store F uses for reputation cache.
   The store's `mirrorVerdict` must match by **CIDR-containment / ASN-lookup** over the synced blacklist
   mirror (P2/Q2), normalising an IPv6 to its /64 before lookup — never exact-match.
3a. **GeoIP adapter (decision R)** — when the operator enables the country gate, implement
   `GeoIpInterface` over the host's **local** GeoIP DB (DB-IP Lite / GeoLite2, reused from the dashboard/
   A1 enrichment); ship + periodically refresh that DB (a data-distribution concern that rides the
   feed/freshness seams). **Never a network call** (R2). Absent → inject `NullGeoIp` and the gate is inert.
4. **Hook / middleware placement** — where in the request lifecycle the engine runs (WP's earliest safe
   `muplugins_loaded`, Laravel middleware, the app's front controller) and at which **position**
   (BEFORE vs FALLBACK) per the config.
5. **Admin UI** — the surface that produces the §8 config array (WP admin screen, Laravel config
   publish, app env) and the learn-then-enforce controls (the shadow→tuning→enforce one-click
   promotions, the kill-switch). The UI is host-specific; the array it produces is identical.

Everything else — the precedence, the ladder, the state machine, pin/TTL, suppression, the two-axis
combination — lives **once**, here. An adapter that reimplements any of that is a bug.

- **The standalone app** additionally gains the **postures** (honeypot/WAF/both) as first-class config;
  STYLE (`FUNNYPOT_STYLE`) stays exactly as-is (it is synthesis config in core, §8/M1).
- **A1 / mainnet is structurally unaffected** (M) — reputation is still consumed via mainnet-client as
  the caller's separate cheap gate; this package just formalizes *how* that verdict is combined.

---

## Key decisions I made (confirm at review)

1. **`evaluate()` returns a `Decision`; the adapter executes it.** The engine is strictly side-effect-
   free (M3). Alternative (the engine performs the block/deceive itself) would couple policy to every
   host's response mechanism and break the framework-free/testable-with-fakes property.
2. **`EvaluatorInterface` is a single port with both `classify()` and `synthesize()`.** Keeps the
   two-phase engine behind one seam so a no-engine deployment injects one no-op; `synthesize` is proven
   (by test) to run only on `deceive`.
3. **`ReputationInterface` forbids a synchronous request-path network call (cache-first only).** M5 is
   enforced at the port contract, not left to the implementation — a fresh lookup is an out-of-band
   warmer that populates F's cache; the request path reads cache/fail-open only.
4. **Reputation is structurally a modifier** — `reputation.as_primary` defaults hard-false and the three
   §4 rules (never primary, never deceive-on-rep-alone, never block-on-rep-alone-by-default) are the
   decision-matrix's invariants, table-tested. This is the single most important FP-safety choice.
5. **Deceive is fenced to counterfactual-404 ∪ specific-signature-past-threshold-on-real-routes; never
   the uncertainty band (M6).** Encoded as the §5 ladder (`allow→log→block→deceive`, deceive above
   block) because a false-positive deceive is silent corruption while a false-positive block is honest.
6. **Learn-then-enforce is per-rule and asymmetric** — promotion human-gated + dwell-AND-volume,
   demotion automatic + instant, with the day-1 sacrificial-path carve-out the one exception. The
   asymmetry is the safety property.
7. **Challenge + tarpit are cut from v1 (M3)** — a PHP-FPM tarpit is a self-DoS; the `Decision` action
   enum is closed at four, with `challenge` an additive future constant.
8. **Config is a plain serializable array via `fromArray()`** (7.3, no named args, M15) — one shape,
   two front-ends (WP admin, Laravel config), so posture/position are config, never code (M4).
9. **Suppression is the iCabbiTools 4-layer model verbatim** (24h dedup / per-IP cap / buffer-collapse /
   score-gate) + the ≥2-source/≥200/90d aggregate rule + allowlist-everywhere/SAFE_PATHS/self_ips/OAST
   backstops — the production-validated numbers baked in, not reinvented.
10. **The deterministic seed is pinned, not just per-request** — a deceived actor's *later* requests
    re-use the pinned seed so deception stays consistent across requests (M5), the anti-unmask property.

## Open items for review

- **Where the out-of-band reputation warmer + the mirror-sync cron run** (which tick populates F's cache
  so the request-path `lookup` is always cache/fail-open, and which cron pulls the thin blacklist artifact
  into `store.mirrorVerdict` per O1). Candidates: the report-drain cron, a dedicated warmer. This spec
  fixes the *contract* (no sync call on the path; mirror-first fresh-read); the *warmer/sync placement* is
  a per-adapter open item.
- **The exact FP-heuristic thresholds for TUNING** (§6) — "otherwise-legit actor" is defined as
  auth-session ∧ clean-reputation ∧ loads-assets ∧ no-other-matches-30d; confirm the conjunction and
  the 30-day window against real WP/Laravel traffic before the first promotion campaign.
- **`RequestEvidence`'s exact field set** — method/path/query/headers/body-shape is enough for the
  precedence and for `classify()`, but confirm the body-shape representation (never the raw body into
  logs, OAST hygiene §9) with core's classify() input needs.
- **Baseline pre-excluded rule set** (§6 `baseline_excluded`) — needs the concrete list of known-FP-
  prone rule ids from core, kept as opaque handles (never signature strings, §10).
- **Confirm `both`-posture double-run cost** — running BEFORE and FALLBACK on one install means two
  `evaluate()` calls per request in the worst case; confirm the cheap gates short-circuit hard enough
  that this is acceptable, or gate the fallback run on the before-run having returned `allow`.

---

## Review resolutions applied (2026-08-19)

Edits reconciling this design with the canonical decisions doc
([`funnypot-mainnet/docs/2026-08-19-program-decisions.md`](../../funnypot-mainnet/docs/2026-08-19-program-decisions.md))
and the future-proofing review
([`funnypot-mainnet/docs/2026-08-19-futureproofing-review.md`](../../funnypot-mainnet/docs/2026-08-19-futureproofing-review.md)).
The design and its sibling plan are kept mutually consistent; everything not implicated below is preserved.

### N/O + future-proofing

- **Fail-safe wording — align §10 to every port (review Minor "Policy fail-safe wording").** §10 previously
  named only evaluator/synthesize faults; it now states that **every** port fault — evaluator/synthesize,
  **reputation**, **store**, logger, clock — degrades to `Decision::allow` and `evaluate()` **never**
  throws, calling out the store (precedence step 2, hit on every request) as the highest-probability throw
  site. §11 testing broadened from "an evaluator that throws" to a per-port fail-safe matrix that
  explicitly covers a **store throw** and a **reputation throw**.
- **O1 fleet-read: local blacklist mirror as a StateStore-backed input (decision O1; review SF-8, fixes
  MF-1's quota math).** The cheapest-first ladder's reputation step (§4 step 4) now consults the synced
  **local blacklist mirror** in the `StateStore` **before** escalating an uncertain (mirror-absent) IP to a
  per-IP reputation check. Added `StateStoreInterface::mirrorVerdict()` (§2.3) returning the synced thin
  row's verdict (`source='mirror'`), added `mirror` to the `ReputationVerdict.source` enum (§2.2), and
  documented in §2.2/§4/§12 that the reputation gate is **cache-first and mirror-first, never a synchronous
  network call** (M5 / decision N) — it consumes F's `cachedVerdict()` and the mirror; a struggling/quota
  mainnet trips F's breaker (N) to a fail-open unknown. Reputation stays a **modifier only** under the
  three §4 rules regardless of source. Added the mirror-before-lookup assertion to §11 and folded the
  mirror-sync cron into the warmer open item.

### P/Q/R entity+geo

Reconciles this design with decisions **P** (IPv6 hardening), **Q** (range/CIDR/ASN reputation — block
ranges, not many IPs), and **R** (country policy via LOCAL GeoIP) from the canonical decisions doc.

- **P2/Q2 — the mirror/gate matching rule: CIDR-containment / ASN-lookup, never exact-match (decisions
  P2, Q1, Q2, Q4).** §2.2 now states that a reputation entry's key may be an IP, a **CIDR** (`/24` v4,
  `/64`/`/48` v6), or an **ASN**, and that **both** the local blacklist mirror (§2.3 `mirrorVerdict`)
  **and** the per-IP lookup resolve a visitor IP by **CIDR-containment / ASN-lookup** — one `/24` row
  covers 256 addresses, one ASN entry a whole network, so the mirror stays small (block ranges, not
  many IPs). Two sub-rules: **an IPv6 is normalised to its `/64` (or the flagged prefix) BEFORE lookup**
  (P2) — never a `/128` exact-match an attacker rotating within a `/64` would evade — and **most-specific
  match wins** (Q4, an exact-IP verdict overrides its containing range; a range-allowlist entry exempts a
  good sub-range). The `mirrorVerdict` docblock (§2.3) and §4 step 4 restate the rule; §8 `allowlist`
  gained an `asns` key and a containment note (the infra allowlist extended to ranges, H2/K3).
- **R — country cheap-static gate in the ladder (decisions R1–R4).** Added **§4 step 3a**, a country
  gate sitting **after allowlist/pin and before reputation/content** (R1). Config (§8 `country`): a
  country **deny-list** OR an **allow-list posture** (the infra allowlist extended to geo — a listed
  country still gets content detection, just skips country-scrutiny). Action is configurable, **DEFAULT
  = score-modifier** (raise scrutiny / arm the reputation-check trigger + suppression); `deceive` and
  `block` are the alternatives — **hard block or the allow-list posture is an explicit operator opt-in**,
  and the **honeypot posture prefers score/deceive over block** (a country block is a tell; deceiving a
  wrongly-flagged legit user is silent corruption — R3/M6). A geo miss falls through (never block on a
  miss). Documented the **blunt-instrument FP caveat** (VPN/CGNAT/roaming/cloud egress — R4).
- **New `GeoIpInterface` port (decision R2).** Added §2.6 `GeoIpInterface::country(string $ip)` →
  `?string` (ISO alpha-2), resolved from a **LOCAL GeoIP DB (DB-IP Lite / GeoLite2), never a network
  call** (M5/R2), resolving both IPv4 and IPv6. Ships a `NullGeoIp` default (gate inert unless the
  operator enables country policy and the adapter wires a real local DB). Renumbered `SiteProfile` →
  §2.7 and the deterministic seed → §2.8; updated the §1 ports diagram (added GeoIp) and the §12
  thin-adapter list (a new "GeoIP adapter" item: ship + refresh the local DB, never a network call;
  the storage adapter's `mirrorVerdict` matches by containment). §12 "zero hard deps" now lists the
  `GeoIp` seam + `NullGeoIp` alongside `Logger`/`Clock`.

### S/T signals+telemetry

Reconciles this design with decisions **S** (request-shape bot signals — individual signals in
`core.classify()`, composite in policy, never a standalone block) and **T** (the S signals ride BOTH the
check and the report; check-carried signals are low-trust async telemetry, never the abuse score, never a
read-path write) from the canonical decisions doc.

- **S1 — signals arrive on the `Verdict`.** §2.1 now carries **`Verdict.botSignals`**, the S request-shape
  set (presence/self-consistency flags + UA class + the digit-stripped, sorted-list structural fingerprint),
  computed in core's `classify()` with each starting weight already folded into `anomalyScore`. Documented as
  **input-side only / never emitted** (fingerprint-safe, §10) and explicitly **not** an outdated-UA/version-age
  check (fragile + high-FP). The §12 funnypot-core ripple gained "compute the S bot-signal set into
  `botSignals` + `anomalyScore`".
- **S2/S3 — composite modifier in the two-axis decision (never a standalone gate).** Added the §4 subsection
  *"Request-shape bot-signals as composite modifiers"*: a single weak signal never `block`s/`deceive`s (S2/M6);
  the signal weights **accumulate** into anomaly/suspicion and **fuse** with reputation (incl. the new
  `ReputationVerdict.usageType` = `context.usage_type=datacenter`, §2.2) × the country modifier (R) — this is
  where **"bot-UA + datacenter IP"** combines (S3). Stated **where the signal-anomaly enters the ladder**: like
  the country modifier it is not a returning gate — it **raises scrutiny, arms the reputation-check escalation
  trigger** (O1/T), and feeds suppression scoring; §4 step 5 notes classify() yields the set as a composite
  modifier only. Ties into §5 — an anomaly-score-only bot-shape never reaches `deceive`.
- **S5 — FP guards apply FIRST.** The §4 subsection states the allowlist/SAFE_PATHS **plus** the SAFE-UA /
  exemption set (monitoring/API/server-to-server/feed readers, `.map` fetches) are checked **before** any
  browser-shape signal counts; an exempt actor's bot-signals are **zeroed, not counted** (legit no-header
  clients carved out specifically, not globally leniently scored). Backed by a new §8 `bot_signals` config
  block (`enabled`, `exempt_uas`, `exempt_paths`, `telemetry`; per-signal weights stay in core, S1) and
  re-checked by the §9 allowlist-everywhere backstop.
- **T — signals ride check + report as low-trust telemetry.** §2.2 states the S set travels on F's
  **out-of-band escalation check** and the **report**, **never** the request-path `lookup` (which stays
  read-only, no write — T3). §9 added the **`bad-bot`-class category + signal-weighted confidence** (S4) and
  the opt-in **`signals` object** on `ReportIntent` (T4/T5), fingerprint-safe (flags/classes only). The §12
  mainnet-client ripple: the policy collects `botSignals` and hands them to the adapter, which attaches the
  `signals` object to F's escalation-check + reporter calls (opt-in `bot_signals.telemetry`); F/A1 async-queue
  it as enrichment/calibration, never the abuse score, never a read-path write (T2/T3). §11 gained a
  bot-signals composite table + a signal-telemetry test bullet.
