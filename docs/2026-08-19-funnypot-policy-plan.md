# metrictower/funnypot-policy · M — implementation plan

**Status:** ready to build · **Date:** 2026-08-19 · **Piece:** M of the funnypot-mainnet program (the 8th piece)
**Implements:** [`2026-08-19-funnypot-policy-design.md`](./2026-08-19-funnypot-policy-design.md) (the design is the source of truth; this plan does not redesign it)
**Canonical (wins over both):** [`funnypot-mainnet/docs/2026-08-19-program-decisions.md`](../../funnypot-mainnet/docs/2026-08-19-program-decisions.md) §M
**Engine contract (dependency):** funnypot-core's two-phase `classify()` + `synthesize()` split (M2) — **not built yet**; this plan builds against a **fake `EvaluatorInterface`** until core lands (see Cross-piece).
**Reputation source:** [`mainnet-client`](../../mainnet-client/docs/2026-08-19-mainnet-client-plan.md) (piece F) — consumed cache-first behind `ReputationInterface`.
**7.3 posture mirrored from:** F's plan (`>=7.3` from birth, `fromArray()` builders, untyped value-object props, its own 7.3 CI lane).

A builder should be able to execute this top to bottom without re-reading the design. Each phase is
TDD: the test is written and shown to fail first, then the code makes it pass, then the **whole suite**
is run green before the next phase starts. Phase 0 stands the package up (the repo does not exist yet).

---

## Orientation

### What exists now (grounding)

- **Nothing in this repo but docs.** `funnypot-policy/` currently holds only `docs/`. Phase 0 creates
  `composer.json`, `phpunit.xml.dist`, `src/`, `tests/`, and a first green (empty) suite. Until Phase 0
  runs, `php vendor/bin/phpunit` has nothing to run.
- **The engine this package holds behind `EvaluatorInterface` does not exist yet.** funnypot-core is
  still the old monolithic responder; its split into `classify()` + `synthesize()` (M2) is a *ripple* of
  this workstream, not a prerequisite for building the policy engine. This package is **entirely testable
  against a `FakeEvaluator`** that scripts a `Verdict` and records whether `synthesize()` was called — so
  it lands and stays green with **zero** dependency on core code. When core's contract lands, the fake is
  swapped for the real adapter at the consumer (D/E/app), not here.
- **Reputation (F) already exists as a plan.** This package does **not** call F directly — it defines
  `ReputationInterface` (cache-first, no sync network call) and the host adapter wires F's
  `ReputationGate`/cache behind it. Tests use a `FakeReputation`.
- **The suppression/scoring numbers are prior-art, not invented.** The 4-layer model (24h verdict-dedup,
  per-IP alert cap 100/600s, buffer-collapse ~900s, score-gate 200), the aggregate-ban (≥2 sources AND
  ≥200 over 90d), and the TTL decay (base 600s, cap 86400s, +1/+10/+100) come from the user's production
  iCabbiTools loop (design §9). Bake them in as the config defaults; do not re-derive.

### How to run the tests (once Phase 0 lands)

- From `funnypot-policy/`: **`composer install`** once (dev-only: phpunit), then **`php vendor/bin/phpunit`**.
  Pure PHPUnit, **no network, no DB, no container**. Every port is a fake (`FakeEvaluator`,
  `FakeReputation`, `ArrayStateStore`, `FixedClock`, `RecordingLogger`); nothing touches a socket, a
  store, or the clock.
- Run one file: `php vendor/bin/phpunit tests/Engine/PrecedenceTest.php`.
- Run one case: `php vendor/bin/phpunit --filter=test_allowlist_beats_malicious_reputation`.
- The security-critical logic (the precedence, the §5 ladder, the state machine, suppression) is
  **table-tested** — one data provider per axis, asserting the exact `Decision.action`.

### Constants fixed by the design (do not re-derive)

- **PSR-4** `Funnypot\Policy\ → src/`; tests a separate autoload-dev root `Funnypot\Policy\Tests\ → tests/`
  (mirrors F/M14). Ports live under `Funnypot\Policy\Port\`.
- **PHP `>=7.3` from birth**, 7.3-clean throughout: **no** constructor promotion, enums, `match`, nullsafe
  `?->`, `??=`, typed properties, union types. Scalar/array/nullable **parameter and return** types
  (`?int`, `?array`, `bool`, `void`, `string`, class names) **are** 7.3-legal and used. Value objects use
  **untyped properties + docblocks**. Config builds via **`PolicyConfig::fromArray()`**, never a
  positional constructor (7.3 has no named args — M15).
- **`evaluate()` returns a `Decision`; it performs NO side effect** (M3). The engine emits no byte, opens
  no socket, writes no store row *itself* — it reads through ports and returns pure data. Any store write
  the engine wants (a pin, a bumped counter, a buffered report) is expressed **through the injected
  `StateStoreInterface`**, never a direct DB touch; the adapter owns execution of the returned action.
- **Fail-safe is the invariant (security invariant 2).** Any port fault — an evaluator/synthesize throw, a
  reputation throw, a store throw — degrades to **`Decision::allow`** (the request-path fallback position
  degrades to a plain 404 in the adapter). `evaluate()` **never** throws on the request path and **never**
  returns a 5xx-shaped decision. A policy fault can only ever fail **open to the real app**.
- **Reputation is a modifier, never primary** (§4, the single most important FP-safety choice). Three hard
  rules, table-tested as invariants: (1) reputation only *modifies* an already-content-suspicious
  request-axis outcome; (2) **never deceive on reputation alone** — deception needs a request-evidence
  signal (a specific matched signal or a sacrificial path); (3) **never block on reputation alone by
  default** — a lone `malicious` on an innocuous request maps to `log`, not `block`, unless the operator
  opted into reputation-block, and even then only at the BEFORE position, never a deceive.
- **Deception governing rule (§5, M6), one review-enforceable sentence:** *deceive where the counterfactual
  is a 404; above the block threshold on real routes; never in the uncertainty band.* On a real route the
  ladder is `allow → log → block → deceive` with **deceive ABOVE block**, reachable only by a specific
  matched signal past threshold — a cumulative anomaly score alone can never reach deceive.
- **Fingerprint-safety by delegation (invariant 1).** `Verdict.matched` is an **opaque handle**, never a
  canonical signature string. The engine never sees/stores/logs/emits a nuclei matcher word, a CRS rule
  id/`msg`, or a ModSecurity/OWASP_CRS marker. `Logger` output and `Decision.reason` are constrained to
  non-sensitive labels (`'allowlist'`, `'pin'`, `'sacrificial-path'`, `'reputation-modifier'`, …), never a
  raw payload or a signature. A dedicated test (`RecordingLogger`) asserts no signature/raw-payload/secret
  ever appears.
- **Status is app-chosen, never model-chosen** (invariant 5) — `Decision.status()` is set by the policy/
  posture (typically `403` for block), never derived from a model; no model-driven 3xx → no open-redirect.
- **OAST hygiene (§9).** Attacker payloads embed callback/OAST URL-shaped paths; the engine records a
  **redacted shape**, never the live attacker-controlled URL, into any log/report/DNS-resolving sink.
- **Actions v1 are closed at four:** `allow | log | block | deceive` (challenge + tarpit **cut** — a
  PHP-FPM tarpit is a self-DoS; M3). `challenge` is an additive future constant, not a redesign.

### Config defaults (design §8 — do not invent others)

`posture='honeypot'`; `position=['fallback'=>true,'before'=>false]`;
`actions=['clean'=>'allow','suspicious'=>'log','attack_class'=>'block','scanner_probe'=>'deceive']`;
`reputation=['enabled'=>false,'block_verdicts'=>['malicious','critical'],'min_block_score'=>null,'as_primary'=>false]`;
`learn=['shadow_days'=>7,'shadow_min_reqs'=>5000,'baseline_excluded'=>[],'kill_switch'=>false]`;
`country=['enabled'=>false,'mode'=>'deny','countries'=>[],'action'=>'modifier']` (decision R — deny-list or
allow-list posture; DEFAULT action `modifier`, `deceive`/`block` opt-in; R3/R4);
`bot_signals=['enabled'=>true,'exempt_uas'=>[],'exempt_paths'=>[],'telemetry'=>false]` (decision S/T — core
computes the per-signal weights in `classify()` (S1), the policy fuses them as a COMPOSITE modifier (S2/S3);
`exempt_uas`/`exempt_paths` are the SAFE-UA/`.map` FP carve-outs applied FIRST (S5); `telemetry` opt-in ships
the signal set to F's escalation-check + report (T));
`pin=['ttl_seconds'=>3600]`;
`suppression=['verdict_dedup_hours'=>24,'per_ip_alert_cap'=>100,'per_ip_cap_window_s'=>600,'buffer_ttl_s'=>900,'score_gate'=>200,'aggregate'=>['min_sources'=>2,'min_total_score'=>200,'window_days'=>90],'decay'=>['base_ttl_s'=>600,'cap_ttl_s'=>86400,'inc_soft'=>1,'inc_medium'=>10,'inc_hard'=>100]]`;
`allowlist=['ips'=>[],'cidrs'=>[],'asns'=>[],'safe_paths'=>[]]` (ips/cidrs/asns matched by containment,
P2/Q2/Q4); `self_ips=[]`.

---

## Phase 0 — Package skeleton + green empty suite

**Change.** Create the package so `phpunit` runs:
- `composer.json`: `name` `metrictower/funnypot-policy`, `type` library, `require { "php": ">=7.3" }`,
  `require-dev { "phpunit/phpunit": "^9.5" }`, `autoload` PSR-4 `Funnypot\\Policy\\ → src/`,
  `autoload-dev` PSR-4 `Funnypot\\Policy\\Tests\\ → tests/`. **Zero hard runtime deps** (no framework, no
  PSR require — `Logger`/`Clock` are local seams with shipped no-op defaults, F posture).
- `phpunit.xml.dist`: one testsuite rooted at `tests/`, `bootstrap="vendor/autoload.php"`, `colors="true"`.
  A `.gitignore` (`/vendor`, `composer.lock` — a library commits no lock).
- `composer install` to generate `vendor/` + the autoloader.
- One placeholder `src/` file (a one-line `Version` const class) so the autoloader has a target, and a
  trivial `tests/SmokeTest.php`.

**Test first.** `tests/SmokeTest.php::test_autoload_and_phpunit_wired` — asserts `true` and that a
namespaced class under `Funnypot\Policy\` autoloads. Its only job is to prove the harness runs.

**Verify green.** `php vendor/bin/phpunit`

**Done when.** `composer install` succeeds; `php vendor/bin/phpunit` runs green (1 test);
`composer validate` passes; the two PSR-4 roots resolve. No product classes beyond the placeholder.

---

## Phase 1 — Ports + input value objects + the port fakes

**Change.** Define the six ports (interfaces only — no logic) and the input data objects, plus the test
doubles every later phase asserts against. **All signatures 7.3-legal** (scalar/array/nullable param+return;
no promotion/enums/`match`/`?->`/typed props/unions).
- `src/Port/EvaluatorInterface.php` (§2.1): `classify(RequestEvidence $r, SiteProfile $p)` → `Verdict`;
  `synthesize(Verdict $v, SiteProfile $p, string $seed)` → `FakeResponse`.
- `src/Port/ReputationInterface.php` (§2.2): `lookup(string $ip)` → `ReputationVerdict`. Contract docblock:
  **MUST NOT make a synchronous network call on the request path** (cache-or-fail-open only) — it consumes
  F's `cachedVerdict()` and the local mirror (O1), never a live socket (M5 / decision N).
- `src/Port/StateStoreInterface.php` (§2.3): the full method set (pins, blocklist, **the local blacklist
  mirror `mirrorVerdict(string $ip)` → `?ReputationVerdict` (O1)**, rule state, suppression ledger, actor
  facts, counters) — declared here, exercised from Phase 2 on. Contract docblock on `mirrorVerdict`:
  matches by **CIDR-containment / ASN-lookup, never exact-match** (P2/Q2); the caller normalises an IPv6
  to its `/64` before lookup; most-specific match wins (Q4).
- `src/Port/GeoIpInterface.php` (§2.6, decision R2): `country(string $ip)` → `?string` (ISO 3166-1
  alpha-2, or null when unresolved). Contract docblock: **MUST NOT make a network call** — resolved from a
  **LOCAL GeoIP DB** (M5/R2); resolves both IPv4 and IPv6. Ship `src/Geo/NullGeoIp.php` (always `null`) as
  the default so the country gate is inert unless the adapter wires a real local DB.
- `src/Port/Clock.php` (§2.4): `now()` → int epoch seconds.
- `src/Port/Logger.php` (§2.5): `log(string $level, string $message, array $context = [])` → void;
  ship `src/Log/NullLogger.php` as the default.
- Input value objects (untyped props + docblocks): `src/RequestEvidence.php` (method/path/query/headers/
  body-shape — **never the raw body**, OAST §9), `src/SiteProfile.php` (§2.7: `stack()`,
  `routeExists(string $path)`, `isSacrificialPath(string $path)`), `src/Verdict.php` (§2.1:
  `classification` `clean|scanner-probe|attack-class|suspicious`, `matched` bool + **opaque** signal
  handle, `anomalyScore` int, `severity` `low|medium|high`, `onRealRoute` bool, **`botSignals`** — the S
  request-shape set (opaque presence/self-consistency flags + UA class + the digit-stripped structural
  fingerprint token, computed in core's `classify()`; input-side only, never a signature string — S1/§10)),
  `src/FakeResponse.php` (`status`, `headers`, `body`, `contentType` — opaque to the engine),
  `src/ReputationVerdict.php` (`verdict` `unknown|clean|suspicious|malicious|critical`, `score` `?int`,
  `source` `mirror|cache|fail-open|absent`, **`usageType`** `?string` — F's `context.usage_type`, e.g.
  `datacenter`, surfaced for the S3 "bot-UA + datacenter IP" fusion).
- Fakes under `tests/Support/`: `FakeEvaluator` (scripts a `Verdict` per request; **records whether
  `synthesize()` was called** and with which seed — proves synthesize runs only on `deceive`),
  `FakeReputation` (scripts a cached verdict; **asserts `lookup` makes no call / never blocks**),
  `FakeGeoIp` (scripts an IP→country map; **asserts `country` makes no network call** and returns null for
  an unmapped IP — the geo-miss fall-through), `FixedClock` (settable epoch), `RecordingLogger` (captures
  every `log()`).

**Test first.** `tests/PortsSmokeTest.php`:
- `test_value_objects_roundtrip` → each input VO constructs and reads back through its getters
  (`SiteProfile.routeExists`/`isSacrificialPath`, `Verdict` fields, `ReputationVerdict.source`).
- `test_fake_evaluator_scripts_verdict_and_records_synthesize` → a scripted `classify` returns the
  scripted `Verdict`; `synthesize` is **not** called until a test calls it, and the fake records the seed.
- `test_fake_reputation_never_calls_out` → `lookup` returns the scripted cached verdict and the fake's
  call-recorder shows no network-shaped call; a fail-open default is `verdict='unknown'`, `source='fail-open'`.
- `test_null_logger_is_noop` and `test_recording_logger_captures` → the shipped `NullLogger` swallows;
  `RecordingLogger` retains level/message/context for later assertions.
- `test_geoip_local_only_and_miss_returns_null` → `FakeGeoIp` returns the scripted country for a mapped IP,
  `null` for an unmapped one (the geo-miss fall-through), and its call-recorder shows no network-shaped call;
  the shipped `NullGeoIp` always returns `null`.

**Verify green.** `php vendor/bin/phpunit tests/PortsSmokeTest.php`

**Done when.** All six ports + all input VOs exist 7.3-clean; the five fakes script/record; `Verdict.matched`
carries an **opaque handle** and **`Verdict.botSignals`** carries opaque flags/UA-class/fingerprint-token (a
test asserts neither requires a signature-shaped string to construct, S1/§10); `ReputationVerdict.usageType`
round-trips (the S3 fusion input); `GeoIpInterface` is local-only (no network call) with a `NullGeoIp`
default; full suite green.

---

## Phase 2 — StateStore value objects + `ArrayStateStore`

**Change.** Add the state value objects (untyped props): `src/Pin.php` (`action`, `seed`, `expiresAt`),
`src/RuleState.php` (`phase` `shadow|tuning|enforced`, `since`, `count`, `exclusions[]`), `src/ActorFacts.php`
(`authSession`, `loadsAssets`, `matches30d`, `firstSeen`), `src/AggScore.php` (`sources[]`, `total`). Add
`tests/Support/ArrayStateStore.php` implementing the full `StateStoreInterface` in-memory against the
injected `FixedClock`: pins with TTL expiry, `isBlocked`, **the local blacklist mirror `mirrorVerdict`
(seedable with thin rows `{score_key, verdict, expires_at}` where `score_key` is an IP, a CIDR, or an
ASN; O1)**, per-rule state get/put + `bumpRuleEvaluated`, the suppression ledger (`seenVerdict` with a
TTL window, `incrAlertCount`, `bufferReport`/`takeReportBuffer`, `aggregateScore`), `actorFacts`, and the
generic windowed `incr`. This is the single seam every stateful phase (6, 8, 9, 10) drives.

`mirrorVerdict` **matches by CIDR-containment / ASN-lookup, not exact-match** (P2/Q2): it normalises an
IPv6 to its `/64` (or the row's prefix) before lookup, returns a row that *contains* the visitor IP,
applies **most-specific match wins** (Q4 — an exact-IP row beats its containing range), and returns null
only when nothing covers the IP (the escalate signal for Phase 6). Containment uses a small pure helper
(`Net::contains(cidr, ip)` / `Net::normaliseV6($ip): string` — 7.3-legal, `inet_pton`-based, no ext
beyond core); ASN rows match when the visitor IP's ASN (supplied on the `RequestEvidence`/enrichment)
equals the row's ASN.

**Test first.** `tests/Support/ArrayStateStoreTest.php`:
- `test_pin_roundtrip_and_ttl_expiry` → `setPin` then `getPin` returns the pin; advance the clock past the
  TTL → `getPin` returns null.
- `test_rule_state_put_get_and_bump` → `putRuleState`/`ruleState` roundtrip; `bumpRuleEvaluated(n)` sums.
- `test_seen_verdict_dedup_window` → first `seenVerdict(key, ttl)` is false (unseen), second within the
  window is true, and after the clock passes the TTL it is false again.
- `test_incr_and_buffer_and_aggregate` → `incrAlertCount` counts within a window; `bufferReport` collapses
  a group and `takeReportBuffer` drains it with the collapsed count; `aggregateScore` returns distinct
  sources + total.
- `test_mirror_verdict_lookup` → a seeded mirror row returns its verdict with `source='mirror'`; an IP not
  in the mirror returns null (the escalate signal for Phase 6).
- `test_mirror_matches_by_cidr_containment_not_exact` → a seeded `/24` CIDR row matches an IP **inside** the
  range (containment), not just the network address, and does not match an IP outside it (P2/Q2).
- `test_mirror_ipv6_normalised_to_64_before_lookup` → a `/64` v6 row matches two different `/128`s inside
  that `/64` (the caller/store normalises to `/64` before lookup — a `/128`-rotating attacker cannot evade;
  P2).
- `test_mirror_most_specific_match_wins` → with both a `/24` range row and an exact-IP row for an IP inside
  it, the exact-IP verdict is returned (Q4); an ASN row matches an IP whose ASN equals the row's ASN.

**Verify green.** `php vendor/bin/phpunit tests/Support/ArrayStateStoreTest.php`

**Done when.** Every `StateStoreInterface` method has a working in-memory backing with clock-driven TTLs;
`mirrorVerdict` matches by CIDR-containment / ASN-lookup (IPv6 normalised to /64, most-specific wins),
never exact-match; the store fake is ready for the engine phases; full suite green.

---

## Phase 3 — `Decision` + `ReportIntent` (the output)

**Change.** Add `src/Decision.php` (§3): the four action constants (`ALLOW='allow'`, `LOG='log'`,
`BLOCK='block'`, `DECEIVE='deceive'`), static factories (`allow()`, `log()`, `block(int $status)`,
`deceive(FakeResponse $f, ?int $pinTtl)`), and getters `action()`, `status()` (`?int`, **app-chosen**),
`fakeHandle()` (`?FakeResponse`, present **iff** action is `DECEIVE`), `pinTtl()` (`?int`), `report()`
(`?ReportIntent`), `reason()` (a non-sensitive label string). Add `src/ReportIntent.php` — a
suppression-shaped, opaque-handle report the adapter may enqueue (§9): `ip`, `resultLabel`, `source`,
`score`, `categories[]` (opaque — includes the S4 `bad-bot` class with a signal-weighted confidence when the
actor is bot-shaped), `dedupKey`, and an optional **`signals`** object (decision T — the S bot-signal set +
local anomaly summary, present only when `bot_signals.telemetry` is enabled; T4/T5) — carrying **no** raw
payload and **no** signature string (the `signals` object is flags/classes/tokens only, §10). A `Decision`
with a `report()` is still side-effect-free; the adapter decides whether to enqueue (and attaches the same
`signals` object to F's out-of-band escalation check — never the request-path `lookup`, T3).

**Test first.** `tests/DecisionTest.php`:
- `test_action_factories_and_getters` → each factory yields the right `action()`; `deceive` carries the
  `FakeResponse` on `fakeHandle()` and every other action's `fakeHandle()` is null.
- `test_deceive_is_the_only_action_with_a_fake` → `allow`/`log`/`block` all return null `fakeHandle()`.
- `test_status_is_settable_not_derived` → `block(403)->status() === 403`; `allow()->status()` is null.
- `test_reason_is_a_plain_label` → `reason()` is one of the allowed non-sensitive labels; a test guards
  that a signature-shaped string is never accepted as a reason.
- `test_report_intent_carries_no_payload` → a constructed `ReportIntent` exposes the dedup key + label +
  opaque categories, and there is no field that could hold a raw body/signature.
- `test_report_intent_signals_opt_in_and_fingerprint_safe` → a `ReportIntent` carries the `signals` object
  (S bot-signal flags/UA-class/fingerprint + anomaly summary) only when supplied, and the object holds
  flags/classes/tokens only — never a raw payload or signature string (T5/§10); a `bad-bot` category with a
  signal-weighted confidence round-trips (S4).

**Verify green.** `php vendor/bin/phpunit tests/DecisionTest.php`

**Done when.** The closed four-action enum + `deceive`-only-fake + app-chosen-status + label-only-reason +
payload-free `ReportIntent` are all proven; full suite green.

---

## Phase 4 — `PolicyConfig::fromArray` + posture presets

**Change.** Add `src/PolicyConfig.php` (§8): untyped props for every documented key, a
`public static function fromArray(array $opts)` builder applying the fixed defaults above, and a getter per
field (`posture()`, `position()`, `actionFor(string $band)`, `reputation()`, `country()`, `botSignals()`,
`learn()`, `pin()`, `suppression()`, `allowlist()`, `selfIps()`). Posture is a **preset selector** (§8): `honeypot`, `WAF`,
`both` each seed `position` + the real-route action ceiling + the reputation-block default *before* the
operator's explicit overrides are layered on top (an explicit `position`/`actions` key in the array wins
over the preset). `as_primary` is **hard-false** — the builder ignores a truthy value with no effect on
`evaluate()` (reputation can never be primary, §4). No engine logic here — pure config shaping.

**Test first.** `tests/PolicyConfigTest.php`:
- `test_from_array_applies_defaults` → `fromArray([])` yields every §8 default (posture `honeypot`,
  fallback-only position, the four band actions, suppression numbers, pin ttl 3600, reputation off).
- `test_posture_presets_seed_position_and_ceiling` → `posture='WAF'` seeds `before` position + a `block`
  real-route ceiling + reputation-block opt-in-able; `posture='both'` seeds before **and** fallback;
  `honeypot` seeds fallback + a `deceive`-at-fallback / `log`-before shape.
- `test_explicit_keys_override_preset` → an explicit `position`/`actions` array overrides the preset value.
- `test_as_primary_is_forced_false` → `reputation.as_primary=true` in the array reads back false.
- `test_suppression_and_learn_defaults` → the 4-layer numbers, the aggregate (2/200/90d), and the decay
  (600/86400/+1/+10/+100) round-trip; `shadow_days=7`, `shadow_min_reqs=5000`.
- `test_country_defaults_off_modifier` → `country()` defaults to `enabled=false`, `mode='deny'`,
  `countries=[]`, `action='modifier'` (decision R — off, and a modifier not a block, by default); an
  explicit `mode='allow'` + `action='block'` round-trips (the opt-in shapes).
- `test_bot_signals_defaults` → `botSignals()` defaults to `enabled=true`, `exempt_uas=[]`, `exempt_paths=[]`,
  `telemetry=false` (decision S/T — signals fused by default as a composite, telemetry opt-in off); explicit
  `exempt_uas`/`exempt_paths` + `telemetry=true` round-trip.
- `test_allowlist_has_asns_key` → `allowlist()` carries the `asns` key (default `[]`) alongside `ips`/
  `cidrs`/`safe_paths` (the Q4 range/ASN allowlist).

**Verify green.** `php vendor/bin/phpunit tests/PolicyConfigTest.php`

**Done when.** One serializable array shape drives posture/position/actions/country/bot_signals/suppression/
learn; presets seed defaults, explicit keys override, `as_primary` is structurally false, `country` defaults
off + modifier, `bot_signals` defaults enabled + telemetry-off, `allowlist` carries `asns`; full suite green.

---

## Phase 5 — Precedence ladder steps 1–3a (allowlist → pin/blocklist → cheap-static → country)

**Change.** Add `src/PolicyEngine.php` with the constructor injecting all **six** ports (Evaluator,
Reputation, StateStore, **GeoIp**, Clock, Logger) + a `PolicyConfig` (untyped props), and
`evaluate(RequestEvidence $e, SiteProfile $p)` → `Decision`. This phase implements the **cheap head** of
the cheapest-first ladder (§4), returning on the first gate that decides:
1. **Allowlist (hard override).** `e.ip` in `allowlist.ips`/`cidrs`/`asns` (matched by **containment /
   ASN-lookup**, P2/Q2/Q4 — a good `/24` inside a listed range is exempt) OR `e.path` in `safe_paths` (the
   `isIgnoredUri` set) OR `e.ip` in `self_ips` → `Decision::allow` with `reason='allowlist'`. Beats
   everything below (proven against a `malicious` reputation in Phase 6).
2. **Local pin / blocklist.** `store.getPin(e.ip)` present → **replay the pinned action with the pinned
   seed** (deception consistency — a deceived actor keeps getting the coherent fake; the pinned
   `FakeResponse` is re-synthesized via the evaluator using the pinned seed). `store.isBlocked(e.ip)` →
   `Decision::block(403)` in a protect-mode posture / `Decision::deceive(...)` in honeypot-mode.
3. **Cheap static.** exact-match malicious-UA (from `e.headers`) OR `p.isSacrificialPath(e.path)` (with
   `p.routeExists(e.path)===false`) → the posture's cheap-static action. A sacrificial path is **deceived**
   (its counterfactual is a 404 — day-1 auto-enforced, §6). **No engine call** at this step.
3a. **Country gate (decision R).** When `country.enabled`, resolve `geo.country(e.ip)` from the LOCAL
   GeoIP DB (§2.6 — **no network call**). Compute a match: in `mode='deny'` the resolved country ∈
   `countries`; in `mode='allow'` the resolved country ∉ `countries` (allow-list posture). On a match,
   apply `country.action`:
   - `modifier` (**DEFAULT**) → set a `countrySuspicion` flag that **raises scrutiny / arms the
     reputation-check trigger + suppression scoring**, then **fall through** to steps 4/5 (the gate does
     not itself return);
   - `deceive` → the posture's deceive (honeypot-preferred, R3/M6);
   - `block` → `Decision::block(403)` (protect-mode; an explicit opt-in — a tell, R3).
   A **geo miss** (unknown country / `NullGeoIp` → `null`) **falls through**, never blocks (R4). The
   allow-list posture is the infra allowlist extended to geo (a listed country still gets content
   detection downstream). **No engine call** at this step.
Steps 4–5 fall through to `Decision::allow` for now (a stub returned at the tail; Phases 6–7 fill them).

**Test first.** `tests/Engine/PrecedenceHeadTest.php` (inject all fakes + a `honeypot` and a `WAF` config):
- `test_allowlisted_ip_allows` / `test_safe_path_allows` / `test_self_ip_allows` → `reason='allowlist'`,
  and the evaluator's `classify` was **never called** (the cheap gate short-circuits).
- `test_allowlist_matches_asn_and_cidr_by_containment` → an IP inside an allowlisted `/24` or under an
  allowlisted ASN allows (containment, not exact-match; Q4).
- `test_pin_replays_action_and_seed` → prime a deceive-pin for an IP; `evaluate` returns `deceive` and the
  `FakeEvaluator` records the **pinned** seed (not a fresh one).
- `test_blocklist_blocks_in_waf_mode` / `test_blocklist_deceives_in_honeypot_mode` → `isBlocked` maps to
  `block(403)` under WAF, `deceive` under honeypot.
- `test_sacrificial_path_deceives_day_one_no_engine_call` → a sacrificial path
  (`isSacrificialPath` true, `routeExists` false) returns `deceive` and `classify` was **never** called.
- `test_malicious_ua_exact_match` → an exact malicious-UA header hits the cheap-static action.
- `test_country_deny_modifier_falls_through_and_arms_scrutiny` → `mode='deny'`, action `modifier`, a
  denied country → the decision **falls through** (not a block/deceive at 3a) and the `countrySuspicion`
  flag is set (asserted via its downstream effect / the recorded reason label); `geo.country` made no
  network call.
- `test_country_deny_block_is_opt_in_and_blocks` → `mode='deny'`, action `block`, a denied country, WAF
  posture → `Decision::block(403)` with `reason='country'`.
- `test_country_allow_posture_acts_on_non_listed` → `mode='allow'`, `countries=['NL']`, action `deceive`,
  a visitor resolved to a non-listed country → the posture's deceive; a visitor resolved to `NL` falls
  through (the geo allow-list is the infra allowlist extended to geo).
- `test_country_geo_miss_falls_through` → `country.enabled`, `NullGeoIp`/unmapped IP → `country(null)` →
  the gate never acts (falls through), never blocks on a miss (R4).
- `test_country_gate_disabled_is_noop` → `country.enabled=false` → `geo.country` is **never called** and
  the gate is skipped entirely.
- `test_nothing_matches_falls_through_to_allow` → an ordinary request with no pin/blocklist/sacrificial/
  country signal returns `allow` (steps 4–5 stubbed).

**Verify green.** `php vendor/bin/phpunit tests/Engine/PrecedenceHeadTest.php`

**Done when.** Steps 1–3a short-circuit cheapest-first with zero engine calls; allowlist matches ips/cidrs/
asns by containment; the pin replays action+seed; sacrificial-path deceives day-one without `classify`; the
country gate acts per deny/allow × modifier/deceive/block (default modifier falls through), resolves from a
local DB with no network call, and falls through on a geo miss; full suite green.

---

## Phase 6 — Reputation gate (step 4) + the two-axis combination + the three rules

**Change.** Add ladder **step 4** (§4): **mirror-first, then cache-first, never a synchronous network
call** (M5 / decision N). The engine first reads `store.mirrorVerdict(e.ip)` — the synced local blacklist
mirror (O1), a cheap `StateStore` read that resolves known-bad IPs with **zero** per-IP credit; **only**
an IP absent from the mirror ("uncertain") escalates to `rep.lookup(e.ip)` — F's cache-first per-IP verdict
(the port contract guarantees no sync call; the engine just consumes the result). **Both reads match by
CIDR-containment / ASN-lookup, never exact-match** (P2/Q2): the engine normalises an IPv6 to its `/64`
before the mirror lookup/report, a range/ASN entry covers every contained IP, and **most-specific match
wins** (Q4). When the country gate (step 3a) set the `countrySuspicion` flag, it feeds here as an added
modifier (arms the reputation-check trigger, R3). Reputation from either source (mirror or cache) is a
**modifier**
folded into the final action under the three hard rules, and it is combined with the request axis (which is
still stubbed as "clean" until Phase 7 wires `classify`, so this phase tests reputation's *lane* using a
scripted request-axis result injected via the `FakeEvaluator`'s pre-classify seam):
- **Rule 1 — modifier only.** Reputation can tighten a threshold, lengthen a pin, or promote a `log` to a
  `block` **on an already-content-suspicious request** — never originate an escalation on its own.
- **Rule 2 — never deceive on reputation alone.** A `malicious` IP on a real existing route with no
  request-evidence signal is **not** deceived (at most `block` in protect-mode, else `log`).
- **Rule 3 — never block on reputation alone by default.** A lone `malicious`/`critical` on an innocuous
  request maps to `log`; only when `reputation.enabled` **and** the verdict is in `block_verdicts`
  (opt-in) **and** the position is BEFORE does it map to `block` — never a `deceive`.
The allowlist (step 1) is re-asserted to beat a `malicious` verdict.

**Test first.** `tests/Engine/ReputationRulesTest.php` (a table over reputation verdict × request-axis ×
posture × position):
- `test_allowlist_beats_malicious_reputation` → allowlisted + `malicious` → `allow`.
- `test_never_deceive_on_reputation_alone` → `malicious` + a real existing route + no request signal →
  never `deceive` (asserts `deceive` is not the action under any posture).
- `test_lone_malicious_on_innocuous_is_log_by_default` → reputation off (default) → `log`, not `block`.
- `test_reputation_block_only_when_opted_in_and_before` → `reputation.enabled` + `block_verdicts` hit +
  BEFORE → `block`; the same at FALLBACK or with reputation off → not `block`.
- `test_reputation_promotes_only_already_suspicious` → a `suspicious` request-axis + `malicious` reputation
  → promoted per rule 1; a `clean` request-axis + `malicious` reputation → still not escalated.
- `test_lookup_makes_no_network_call` → the `FakeReputation` call-recorder shows zero network-shaped calls
  on the request path.
- `test_mirror_consulted_before_per_ip_lookup` → an IP present in `store.mirrorVerdict` resolves from the
  mirror and `FakeReputation.lookup` is **never** called (O1); a mirror-absent IP escalates to `lookup`.
- `test_mirror_matches_range_by_containment` → an IP inside a seeded mirror `/24` (or under a seeded ASN
  row) resolves from the mirror by containment; an IPv6 `/128` inside a seeded `/64` resolves after the
  engine normalises it to `/64` (P2/Q2); an exact-IP row beats its containing range (Q4).

**Verify green.** `php vendor/bin/phpunit tests/Engine/ReputationRulesTest.php`

**Done when.** Reputation is provably a mirror-first, cache-first modifier bound by the three rules; the
mirror is consulted before any per-IP lookup (O1); both reads match by CIDR-containment / ASN-lookup with
IPv6 normalised to /64 and most-specific-match-wins (P2/Q2/Q4); the allowlist beats it; no sync call on the
path; full suite green.

---

## Phase 7 — Engine `classify()` (step 5) + the §5 deception governing rule

**Change.** Add ladder **step 5** (§4): `evaluator.classify(e, p)` — **last, the expensive gate** —
producing the request-evidence `Verdict`, combined with the Phase-6 reputation modifier and the per-rule
phase (still SHADOW-agnostic until Phase 9) to pick the final action per the §5 ladder. Encode the
governing rule (M6):
- **Counterfactual-404 paths** (`p.routeExists(e.path)===false` — sacrificial/unrouted): deception is
  FP-free by construction → may `deceive`.
- **Real routes** (`routeExists` true): ladder `allow → log → block → deceive`, **deceive above block**.
  `deceive` is reached **only** by a **specific matched signal past threshold** (`Verdict.matched===true`
  with severity/anomaly past the band). A cumulative anomaly score **alone** (no specific match) reaches at
  most `log` (or `block` in protect-mode) — **never** `deceive`.
- **Uncertainty band** (suspicious, accumulating anomaly, no specific match): `log`, or `block` in a strict
  protect-mode — **never** `deceive`.
`synthesize()` is invoked **only** when the chosen action is `deceive`; the `FakeEvaluator` records that
`synthesize` ran only on those cases.

**Bot-signal composite fusion (decisions S2/S3/S5).** `classify()` yields `Verdict.botSignals` (the S
request-shape set) alongside the classification. Fold it into the two-axis combination as a **composite
modifier only**:
- **FP guards FIRST (S5).** Before any browser-shape signal is counted, apply the carve-outs — the step-1
  allowlist/SAFE_PATHS **and** the `bot_signals.exempt_uas` SAFE-UA set + `bot_signals.exempt_paths` (e.g.
  `*.map`). An exempt actor's `botSignals` are **zeroed, not counted** (a legit no-header monitoring/API/feed
  client carved out specifically, not globally leniently scored).
- **Composite, never alone (S2/M6).** A single weak signal never `block`s/`deceive`s; the weights (already in
  `anomalyScore` from core, S1) accumulate to **raise scrutiny** and **arm the reputation-check escalation
  trigger**; a scanner-UA is decisive only as an unambiguous tool signature. An anomaly-score-only bot-shape
  with no specific matched signature reaches at most `log`/`block` — **never** `deceive` (§5, the existing rule
  below covers it).
- **Fusion (S3).** The composite fuses with the Phase-6 reputation modifier — including
  `ReputationVerdict.usageType='datacenter'` — and the step-3a country modifier: "bot-UA + datacenter IP"
  escalates scrutiny where either alone would not. `bot_signals.enabled=false` ignores the set entirely.

**Test first.** `tests/Engine/DeceptionRuleTest.php`:
- `test_deceive_on_counterfactual_404` → a specific match on a `routeExists=false` path → `deceive`, and
  `synthesize` was called.
- `test_deceive_on_specific_signal_past_threshold_real_route` → `matched=true` past threshold on a real
  route → `deceive` (deceive above block).
- `test_anomaly_score_alone_never_deceives` → high cumulative `anomalyScore`, `matched=false`, real route →
  `log`/`block`, **never** `deceive` (asserts synthesize was **not** called).
- `test_uncertainty_band_never_deceives` → `classification='suspicious'`, no specific match → `log`
  (default posture) / `block` (strict protect-mode), never `deceive`.
- `test_synthesize_runs_only_on_deceive` → across the whole table, `FakeEvaluator` recorded a `synthesize`
  call **iff** the action was `deceive`.
- `test_classify_is_the_last_gate` → for every earlier-gate decision (allowlist/pin/sacrificial), `classify`
  was never called (re-asserts the cost gradient end-to-end).

Plus `tests/Engine/BotSignalCompositeTest.php` (decisions S2/S3/S5) — a table over (bot-signal set ×
`usageType` × country modifier × posture):
- `test_single_weak_signal_never_blocks_or_deceives` → one bot-signal (empty UA, or a lone missing header)
  only raises the anomaly/scrutiny; the action stays `allow`/`log`, never `block`/`deceive` (S2/M6).
- `test_bot_signal_plus_datacenter_fuses` → a bot-shape request + `ReputationVerdict.usageType='datacenter'`
  escalates scrutiny where either alone would not (S3, "bot-UA + datacenter IP"); the same with a scrutinised
  country modifier adds, not each independently gating.
- `test_anomaly_only_bot_shape_never_deceives` → a high accumulated bot-signal anomaly with no specific
  matched signature reaches at most `log`/`block`, never `deceive` (S5→§5); `synthesize` not called.
- `test_fp_guards_zero_signals_first` → an `exempt_uas`/`exempt_paths`(`*.map`)/allowlisted actor's
  `botSignals` are **zeroed, not counted** (carved out specifically), while a non-exempt no-header client
  still accrues the anomaly (S5).
- `test_bot_signals_disabled_ignores_set` → `bot_signals.enabled=false` → the set contributes nothing.

**Verify green.** `php vendor/bin/phpunit tests/Engine/DeceptionRuleTest.php tests/Engine/BotSignalCompositeTest.php`

**Done when.** The full cheapest-first ladder returns a `Decision`; deceive is fenced to counterfactual-404
∪ specific-signal-past-threshold, never the uncertainty band; `synthesize` runs only on `deceive`; the S
bot-signals fuse as a composite modifier (never alone, FP-guards-first, datacenter/country fusion — S2/S3/S5);
full suite green.

---

## Phase 8 — Deterministic seed + pin/TTL deception consistency

**Change.** Add the seed + pin write. A stable per-actor seed `sha1(actorId + siteSalt)` (actorId = the
normalized source IP, or a session/actor token the adapter supplies) flows into `synthesize()` so a
stateless engine yields a coherent multi-step fake (§2.8). On a `deceive` decision, the engine returns a
`Decision` carrying `pinTtl` (from `config.pin.ttl_seconds`); the **adapter** performs the write, but the
engine expresses it by pinning through `store.setPin(ip, action, seed, ttl)` on the same decision path so a
**later** request from the deceived actor replays the identical seed (Phase 5 step 2). Prove the loop:
first deceive pins seed S; a second request from the same actor hits the pin and re-uses S → the two fakes
derive from the same seed (anti-unmask). The seed is also used to derive a coherent block/deceive across a
multi-path probe from one actor.

**Test first.** `tests/Engine/SeedAndPinTest.php`:
- `test_deceive_pins_seed_with_ttl` → a first deceive sets a pin whose `seed` equals the derived
  `sha1(actorId+salt)` and whose `expiresAt` is `now + pin.ttl_seconds`.
- `test_later_request_replays_same_seed` → a second request from the same actor within the TTL is served
  from the pin with the **identical** seed (the `FakeEvaluator` records the same seed twice).
- `test_pin_expires_and_reseeds` → advance the clock past the TTL → the pin is gone, a fresh evaluation
  runs (still the same deterministic seed for the same actorId, but a fresh classify).
- `test_seed_is_deterministic_per_actor` → two evaluations for the same actorId derive the same seed; two
  different actorIds derive different seeds.
- `test_multi_path_probe_is_coherent` → the same actor probing `/admin` then `/admin/config` derives fakes
  from one seed (both `synthesize` calls recorded with the same seed).

**Verify green.** `php vendor/bin/phpunit tests/Engine/SeedAndPinTest.php`

**Done when.** A deceived actor is pinned with a deterministic seed + TTL; later requests replay it; the
seed is stable per actor and unique across actors; full suite green.

---

## Phase 9 — Learn-then-enforce state machine + scoped exclusion compiler + day-1 carve-out

**Change.** Add `src/Learn/StateMachine.php` driving per-**rule** promotion (§6), asymmetric — promotion
human-gated and slow, demotion automatic and instant — over `store.ruleState(ruleId)`:
- **SHADOW** — the rule runs and logs but its action is **forced to `log`** regardless of what it wanted.
  Leave gate: **min `shadow_days` (7) AND min `shadow_min_reqs` (5000) evaluated requests** — both
  (`store.bumpRuleEvaluated` counts; `Clock` provides dwell). Neither alone promotes.
- **TUNING** — compile **scoped exclusion tuples** `(rule_id, path_prefix, param)` — **never a global
  disable** — from the FP heuristic: the rule matched an **otherwise-legit** actor = auth-session ∧
  clean-reputation ∧ loads-assets ∧ **no other rule matches in 30d** (all read from `store.actorFacts`).
  A **human approve** step is required; a **baseline of `learn.baseline_excluded` rule ids ships
  pre-excluded** (the paranoia-level-1 analog).
- **ENFORCED** — per-rule, one click, only after **zero suspected FPs in the window**; the rule's intended
  action (block/deceive per posture + §5) now applies.
- **Auto-demote (automatic, instant)** — any ENFORCED rule that fires on an actor **subsequently proven
  legit** (later authenticated, reputation resolved clean, or operator-whitelisted) → **demote to SHADOW +
  raise an alert**, no human. A **global kill-switch** (`learn.kill_switch`) demotes every rule at once.
- **DAY-1 sacrificial-path carve-out** — the one exception: counterfactual-404 rules
  (`isSacrificialPath` ∧ `routeExists=false`) **auto-enforce on install day** (FP cost zero by
  construction, §6); no real-route rule ever skips SHADOW.
The engine consults the rule phase when picking the final action (a SHADOW rule forces `log`).

**Test first.** `tests/Learn/StateMachineTest.php`:
- `test_shadow_forces_log_regardless_of_wanted_action` → a rule that "wants" `block`/`deceive` in SHADOW
  yields `log`.
- `test_promotion_needs_both_dwell_and_volume` → 7 days but <5000 reqs → stays SHADOW; 5000 reqs but <7
  days → stays SHADOW; both satisfied → eligible for TUNING (assert neither alone promotes).
- `test_tuning_compiles_scoped_exclusion_not_global` → the FP heuristic on an otherwise-legit actor
  compiles a `(rule_id, path_prefix, param)` tuple; assert it is **scoped**, never a global disable.
- `test_baseline_excluded_ships_pre_excluded` → rule ids in `learn.baseline_excluded` start with the
  exclusion present.
- `test_human_approve_required_before_enforced` → without the approve step the rule cannot reach ENFORCED.
- `test_enforced_auto_demotes_on_proven_legit_and_alerts` → an ENFORCED rule hitting a proven-legit actor
  demotes to SHADOW and a demotion alert is recorded, with **no** human step.
- `test_global_kill_switch_demotes_all` → `kill_switch=true` forces every rule to SHADOW at once.
- `test_day1_sacrificial_path_auto_enforces_while_real_route_shadows` → on a fresh config, a sacrificial
  path is **immediately** deceived while a real-route attack-class rule is still only `log` (shadow).

**Verify green.** `php vendor/bin/phpunit tests/Learn/StateMachineTest.php`

**Done when.** SHADOW forces log; promotion needs dwell-AND-volume; TUNING compiles scoped (never global)
exclusions with a human gate + pre-excluded baseline; auto-demote + kill-switch work without a human; the
day-1 carve-out enforces sacrificial paths only; full suite green.

---

## Phase 10 — Suppression layers + scoring decay + aggregate-ban + backstops

**Change.** Add `src/Report/Suppressor.php` producing (or withholding) the `Decision.report()`
`ReportIntent` through the 4-layer iCabbiTools model (§9), all keyed through `StateStore`:
1. **24h verdict-dedup** — `store.seenVerdict(sha1(ip+result+source), 24h)`: one intent per identical
   verdict per window.
2. **Per-IP alert cap** — `store.incrAlertCount(ip, 600s)` stops at **100/600s**.
3. **Buffer-and-collapse** — `store.bufferReport(groupKey, report, 900s)` collapses a group into one
   message rendered `(×N)`; `takeReportBuffer` drains.
4. **Score-gate** — an intent fires only when the actor's **decayed score** clears `score_gate` (200).
Add the **TTL-decay accumulator** feeding the gate: base 600s, cap 86400s; increments **+1 soft / +10
medium / +100 hard-tell** (hard tell = effectively instant), read-time decay (the G1 shape — drifts down
without a sweep). Add the **aggregate-ban** rule: escalate only with **≥2 distinct sources AND
total_score ≥ 200 over 90 days** (`store.aggregateScore`). Add the **backstops re-checked at EVERY
mutating point** (score/report/pin/block): allowlist-everywhere, `safe_paths`/`isIgnoredUri`, `self_ips`,
and **OAST hygiene** — an OAST/URL-shaped path is recorded as a **redacted shape**, never forwarded
verbatim. **Bot-signal report evidence (S4/T):** a bot-shaped actor's surviving `ReportIntent` carries the
`bad-bot` category + a **signal-weighted confidence** (S4), and — **only** when `bot_signals.telemetry` is on
— the opt-in **`signals`** object (T4/T5), fingerprint-safe (flags/classes/tokens only). The suppression
quorum still applies (a lone source cannot list, D4); the adapter attaches the identical `signals` object to
F's out-of-band escalation check, never the request-path `lookup` (T3).

**Test first.** `tests/Report/SuppressionTest.php`:
- `test_verdict_dedup_one_per_24h` → the identical `sha1(ip+result+source)` emits one intent per window;
  a distinct source/result emits again.
- `test_per_ip_cap_stops_at_100_per_600s` → the 101st alert in the window is suppressed; the window rolls.
- `test_buffer_collapses_burst_to_one_with_count` → N grouped reports drain as one intent carrying `(×N)`.
- `test_score_gate_suppresses_below_200` → an actor below the decayed-score gate is recorded but not
  alerted; crossing 200 alerts.
- `test_decay_increments_and_read_time_decay` → +1/+10/+100 increments accumulate; advancing the clock
  decays the read value toward the base without a sweep; a hard-tell alone crosses the gate instantly.
- `test_aggregate_ban_needs_two_sources_and_200_over_90d` → one source at ≥200 → no ban; ≥2 distinct
  sources AND ≥200 within 90d → ban recommendation; outside the window → no ban.
- `test_backstops_suppress_at_every_mutating_point` → an allowlisted / `self_ips` / `safe_paths` actor is
  never scored or reported even when a downstream layer would have.
- `test_oast_shaped_path_is_redacted_never_verbatim` → an OAST/URL-shaped path in the evidence is recorded
  as a redacted shape; the live attacker-controlled URL never appears in the `ReportIntent` or the logger.
- `test_bad_bot_category_and_opt_in_signals` → a bot-shaped actor's `ReportIntent` carries the `bad-bot`
  category + signal-weighted confidence (S4); the `signals` object is present **only** when
  `bot_signals.telemetry=true` (T4) and holds flags/classes/tokens only — never a raw payload/signature
  (T5/§10); telemetry-off emits no `signals`.

**Verify green.** `php vendor/bin/phpunit tests/Report/SuppressionTest.php`

**Done when.** The 4 layers + read-time decay + aggregate-ban + the allowlist/self_ips/SAFE_PATHS/OAST
backstops all gate the `ReportIntent`; the prior-art numbers match §8/§9; full suite green.

---

## Phase 11 — Default install posture + both-posture double-run + fail-safe

**Change.** Wire the §7 default-install behavior and the fail-safe invariant into `evaluate()`:
- **FALLBACK position deceives everything** unmatched (FP-free by construction — a request that reached the
  404 fallback had no real route); the classic honeypot works on install day with zero tuning.
- **BEFORE position runs only the FP-free-by-construction gates immediately** — sacrificial-path deception,
  local blocklist, extreme-reputation block **only if opted in** — and holds **every real-route detection
  rule in SHADOW** (Phase 9).
- **`both` posture** runs BEFORE **and** FALLBACK; gate the fallback run on the before-run having returned
  `allow` so the worst-case double `evaluate()` short-circuits hard (design Open item).
- **Fail-safe (security invariant 2):** wrap the port calls so an evaluator/synthesize/reputation/store/
  **geoip** **throw** degrades to `Decision::allow` (the adapter renders a plain 404 at the fallback),
  never a 5xx, never an uncaught throw on the request path.

**Test first.** `tests/Engine/PostureAndFailsafeTest.php`:
- `test_fallback_deceives_everything_on_fresh_install` → default honeypot config, an unmatched request at
  FALLBACK → `deceive`, no tuning required.
- `test_before_runs_only_fp_free_gates_rest_shadow` → default config at BEFORE: a sacrificial path deceives,
  a real-route attack-class rule only `log`s (shadow), reputation-block off → `log` not `block`.
- `test_both_posture_short_circuits_on_allow` → `posture='both'`: a request the before-run `allow`s
  triggers the fallback run; a before-run non-allow does **not** double-run.
- `test_evaluator_throw_degrades_to_allow` → a `FakeEvaluator` whose `classify` throws → `evaluate` returns
  `Decision::allow`, never propagates, never a 5xx-shaped decision.
- `test_synthesize_throw_degrades_to_allow_not_500` → a `synthesize` throw on a would-be deceive degrades
  to `allow` (the fallback adapter's plain 404), never an escaped 500.
- `test_store_throw_degrades_to_allow` → a `StateStore` throw anywhere on the path (the highest-probability
  site — the store is read on every request at precedence step 2, incl. the pin/mirror read) → `allow`.
- `test_reputation_throw_degrades_to_allow` → a `ReputationInterface` throw on the step-4 mirror/cache read
  → `evaluate` returns `Decision::allow`, never propagates.
- `test_geoip_throw_degrades_to_allow` → a `GeoIpInterface` throw on the step-3a country lookup →
  `evaluate` returns `Decision::allow`, never propagates (the country gate can never take the site down).

**Verify green.** `php vendor/bin/phpunit tests/Engine/PostureAndFailsafeTest.php`

**Done when.** Fresh-install fallback-deceives / before-shadows; `both` short-circuits; every port throw
fails open to `allow` (never a 500); full suite green.

---

## Phase 12 — 7.3 CI lane (the package's own gate)

> This package is framework-free `>=7.3` and consumed by the WP host (D). It carries its **own** 7.3 lane
> (design §11), independent of core's matrix.

**Change.** Add `.github/workflows/ci.yml` with a **PHP 7.3** job: a `php:7.3` runner, `composer install`,
then `php vendor/bin/phpunit`. Add a lint step (`php -l` over `src/`, or PHPCompatibility set to 7.3) as a
fast fail so no 7.4+ construct (typed props, `match`, `?->`, `??=`, promotion, unions, enums) slips in.
Optionally add an 8.x job so both interpreters stay green. Document the local one-off:
`docker run --rm -v "$PWD":/app -w /app php:7.3-cli php -l` over `src/`. No network/DB extensions needed —
the suite is pure (every port is a fake).

**Test first.** No product test — the artifact is the workflow. Prove it by a green 7.3 run in CI (or the
local `php:7.3-cli` parse + suite run).

**Verify.** CI 7.3 job green; local `php:7.3-cli -l src/` exits 0; `php vendor/bin/phpunit` green on 7.3.

**Done when.** The package's own 7.3 lane is green; a lint step guards against 7.4+ constructs; the dev
host being 8.x is backstopped by the 7.3 job as the authoritative syntax check.

---

## Cross-piece dependencies (coordination)

- **funnypot-core's two-phase contract (M2) is the one hard dependency — and it is NOT built yet.** This
  plan builds entirely against `FakeEvaluator`, so all 13 phases land and stay green with **zero** core
  code. Core's ripple (split the responder into `classify()` + `synthesize()`; add `SiteProfile` + `seed`
  inputs; stay position-blind/action-free; **compute the S request-shape bot-signal set into
  `Verdict.botSignals` + `anomalyScore`** — the digit-stripped structural fingerprint + presence/
  self-consistency flags + UA class, input-side only and never emitted, S1) is tracked in core's own spec/
  plan. When it lands, the **host adapter** (D/E/app) injects the real evaluator into `PolicyEngine` — **no
  change to this package**. If core's `Verdict`/`FakeResponse`/`SiteProfile` field set drifts from §2 (incl.
  the `botSignals` shape), reconcile the input VOs here.
- **mainnet-client (F) via `ReputationInterface`.** Reputation is consumed cache-first behind the port; the
  adapter wires F's `ReputationGate`/cache and surfaces F's `context.usage_type` as `ReputationVerdict.usageType`
  (the S3 fusion input). The earlier "reputation-block feature" (F's D/E ripple) **becomes the opt-in modifier
  of §4** here, not a standalone gate. **Signal telemetry (decision T):** the policy collects `Verdict.botSignals`
  and the adapter attaches the opt-in `signals` object (gated by `bot_signals.telemetry`) to F's **out-of-band
  escalation check + the reporter call** — never the request-path `lookup` (T3). F's ripple: accept a `signals`
  object on check + report; A1 async-queues it as low-trust enrichment/calibration, never the abuse score, never
  a read-path write (T2/T3). F is otherwise structurally unaffected.
- **D / E / app adapters (THIN — M's ripple).** Each keeps only: request normalization → `RequestEvidence`
  + `SiteProfile` (the real-route oracle — only the host knows its routes); `Decision` execution
  (`allow`/`log` → real app; `block` → honest 403; `deceive` → emit `fakeHandle`; status from the
  `Decision`, never invented); a `StateStoreInterface` over the host store (the **same** store F uses,
  whose `mirrorVerdict` matches by CIDR-containment / ASN-lookup, P2/Q2); **a `GeoIpInterface` over the
  host's local GeoIP DB when the country gate is enabled** (DB-IP Lite / GeoLite2, shipped + refreshed,
  never a network call — R2; else `NullGeoIp`); hook/middleware placement + position; and the admin UI that
  produces the §8 config array (incl. the `country` **and `bot_signals`** policy) + the learn-then-enforce
  one-click promotions. **Signal telemetry (decision T):** the adapter attaches the policy's opt-in `signals`
  object to F's out-of-band escalation check + reporter call (gated by `bot_signals.telemetry`), never the
  request-path `lookup` (T3). **Any adapter that reimplements the precedence, the ladder, the state machine,
  pin/TTL, or suppression is a bug** — those live once, here.
- **standalone app** additionally gains the postures (honeypot/WAF/both) as first-class config; STYLE
  (`FUNNYPOT_STYLE`) stays as-is (synthesis config in core).
- **A1 / mainnet is structurally unaffected** — reputation is still consumed via mainnet-client as the
  caller's separate cheap gate.

## Risks & open decisions

1. **Core's two-phase contract is unbuilt (highest coupling).** The `FakeEvaluator` lets this package land
   first, but the `Verdict`/`FakeResponse`/`SiteProfile` shapes in §2 are this plan's *assumption* of core's
   output. Confirm them against core's spec before the adapter wires the real evaluator; a field drift is a
   VO reconciliation here, not a redesign. **Open (design §12).**
2. **Reputation-as-modifier is the FP-safety keystone.** The three §4 rules are table-tested invariants
   (Phase 6). Any future "reputation can escalate on its own" request must be rejected at review — it
   reintroduces the shared-egress-outage / CGNAT-neighbor failure modes the rules exist to prevent.
3. **The FP-heuristic thresholds for TUNING (§6) are unvalidated.** "Otherwise-legit actor" =
   auth-session ∧ clean-reputation ∧ loads-assets ∧ no-other-matches-30d; confirm the conjunction and the
   30-day window against real WP/Laravel traffic before the first promotion campaign. **Open (design §12).**
4. **`both`-posture double-run cost.** Two `evaluate()` calls per request in the worst case; Phase 11 gates
   the fallback run on the before-run returning `allow` and relies on the cheap gates short-circuiting
   hard. Confirm the short-circuit is tight enough under load. **Open (design §12).**
5. **`RequestEvidence` body-shape representation.** Method/path/query/headers/body-shape is enough for the
   precedence and `classify()`, but the body-shape must never carry the raw body into logs (OAST §9);
   confirm the representation against core's `classify()` input needs. **Open (design §12).**
6. **Baseline pre-excluded rule set (`learn.baseline_excluded`).** Needs the concrete list of known-FP-prone
   rule ids from core, kept as **opaque handles** (never signature strings, §10). Ships empty until core
   supplies them. **Open (design §12).**
7. **The out-of-band reputation warmer placement.** This package fixes the *contract* (no sync call on the
   path); which tick populates F's cache (report-drain cron vs a dedicated warmer) is a **per-adapter** open
   item, not built here. **Open (design §12).**

## Definition of done

- `Funnypot\Policy\{PolicyEngine, PolicyConfig, Decision, ReportIntent, RequestEvidence, SiteProfile,
  Verdict, FakeResponse, ReputationVerdict, Pin, RuleState, ActorFacts, AggScore}`, the ports
  `Port\{EvaluatorInterface, ReputationInterface, StateStoreInterface, GeoIpInterface, Clock, Logger}` +
  `Log\NullLogger` + `Geo\NullGeoIp` + the `Net` containment helper, the `Learn\StateMachine`, and the
  `Report\Suppressor` all exist under `src/`, **all 7.3-syntax-clean** (untyped props; scalar/array/
  nullable param+return types kept).
- `php vendor/bin/phpunit` green from `funnypot-policy/`, covering: the cheapest-first ladder
  (allowlist hard-override → pin-replay-seed → cheap-static/sacrificial-day-1 → country-gate →
  reputation-modifier → `classify` last), each earlier gate proven to make **no** engine call; allowlist +
  mirror + reputation matched by CIDR-containment / ASN-lookup with IPv6 normalised to /64 (P2/Q2/Q4); the
  country gate (deny/allow × modifier/deceive/block, default modifier falls through, local GeoIP no network
  call, geo-miss falls through); the three reputation rules
  (never-primary / never-deceive-on-rep-alone / never-block-on-rep-alone-by-default) + allowlist-beats-
  malicious; the §5 deception rule (deceive on counterfactual-404 ∪ specific-signal-past-threshold, never
  on anomaly-score-alone, never in the uncertainty band) with `synthesize` proven to run **iff** `deceive`;
  the S bot-signal composite (single weak signal never blocks/deceives; fuses with `usageType=datacenter` +
  country; FP-guards zero exempt/`.map`/allowlisted actors' signals FIRST; `enabled=false` ignores — S2/S3/S5)
  + the signal telemetry (`bad-bot` category + signal-weighted confidence; opt-in `signals` on report +
  escalation-check, never the request-path `lookup`; fingerprint-safe — S4/T);
  the seed/pin deception-consistency loop (later requests replay the same seed); the learn-then-enforce
  machine (SHADOW forces log; promotion needs dwell-AND-volume; scoped-not-global exclusions with a human
  gate + pre-excluded baseline; auto-demote + kill-switch without a human; day-1 sacrificial carve-out);
  the 4-layer suppression + read-time decay + aggregate-ban + allowlist/self_ips/SAFE_PATHS/OAST backstops;
  and the default-install posture + `both` short-circuit.
- **`evaluate()` never throws and performs no side effect** — every port fault degrades to `Decision::allow`
  (the adapter's plain 404 at the fallback), never a 5xx (security invariant 2); the returned `Decision` is
  pure data the adapter executes.
- **No fingerprint leak** — `Verdict.matched` is an opaque handle, `Decision.reason`/`ReportIntent`/logger
  output carry only non-sensitive labels, and a `RecordingLogger` test asserts no signature/raw-payload/
  secret ever appears; **status is app-chosen** (no model-driven 3xx).
- **Zero hard runtime deps** (`composer install` on a bare 7.3 host succeeds and the suite runs); PSR-4
  roots resolve; `composer validate` passes.
- The package's **own 7.3 CI lane** (Phase 12) is green with a lint step guarding 7.4+ constructs.
- **No RCE surface** — the package only reads request evidence + config and returns data; it `require`s
  nothing derived from a request (unlike the rules-updater).

## Key decisions I made (confirm at review)

1. **Thirteen phases (0–12), primitives-up then engine then policy layers.** Skeleton → ports+VOs+fakes →
   state VOs+store → Decision → Config/presets → ladder head (1–3) → reputation (4) → classify+§5 (5) →
   seed/pin → state machine → suppression → posture+fail-safe → 7.3 lane. Every phase keeps `phpunit` green.
2. **Build entirely against a `FakeEvaluator`.** Core's two-phase contract is unbuilt; the fake makes this
   package land first and stay green with zero core code, and proves (by test) `synthesize` runs only on
   `deceive`. The real evaluator is injected by the adapter, never by this package.
3. **The precedence ladder is split across three phases (5/6/7)** in strict cost order so each gate's
   short-circuit (no engine call before it decides) is proven incrementally, not in one large step.
4. **Reputation gets its own phase (6) with the three rules as table-tested invariants** — the single most
   important FP-safety property, worth isolating from the request-axis logic.
5. **The §5 deception rule is its own phase (7)** — deceive-above-block, fenced to counterfactual-404 ∪
   specific-signal, `synthesize`-only-on-deceive — because a false-positive deceive is silent corruption
   while a false-positive block is honest.
6. **Seed/pin (8) precedes the state machine (9)** so deception-consistency is proven before the
   learn-then-enforce promotion logic layers on top.
7. **Suppression (10) reuses the iCabbiTools numbers verbatim** as config defaults (Phase 4), not
   reinvented; the backstops are re-checked at every mutating point, not just the ladder head.
8. **Fail-safe is folded into the posture phase (11)** as an `evaluate()`-wide guard: every port throw →
   `Decision::allow`, matching the honeypot's "the LLM only ever upgrades a 404" invariant.

---

## Review resolutions applied (2026-08-19)

Edits reconciling this plan with the canonical decisions doc
([`funnypot-mainnet/docs/2026-08-19-program-decisions.md`](../../funnypot-mainnet/docs/2026-08-19-program-decisions.md))
and the future-proofing review
([`funnypot-mainnet/docs/2026-08-19-futureproofing-review.md`](../../funnypot-mainnet/docs/2026-08-19-futureproofing-review.md)),
kept mutually consistent with the design's matching subsection. Everything not implicated is preserved.

### N/O + future-proofing

- **Fail-safe: reputation-throw test added (review Minor "Policy fail-safe wording").** The Orientation
  invariant already covered every port; Phase 11 kept only evaluator/synthesize/store fail-safe tests. Added
  `test_reputation_throw_degrades_to_allow` alongside the existing `test_store_throw_degrades_to_allow`
  (annotated as the highest-probability site — the store is read on every request at precedence step 2), so
  the plan proves both the store-throw and reputation-throw degrade-to-`allow` paths the review named.
- **O1 fleet-read: local blacklist mirror in the StateStore (decision O1; review SF-8, fixes MF-1).** Phase 1
  declares `StateStoreInterface::mirrorVerdict()` and adds `mirror` to the `ReputationVerdict.source` enum;
  Phase 2 backs it in `ArrayStateStore` (seedable thin rows, null when absent) with `test_mirror_verdict_lookup`;
  Phase 6's step 4 becomes **mirror-first, then cache-first** — the engine reads `store.mirrorVerdict(e.ip)`
  before escalating an uncertain (mirror-absent) IP to `rep.lookup()`, proven by
  `test_mirror_consulted_before_per_ip_lookup`. Reputation stays a cache-first modifier that never makes a
  synchronous request-path network call (M5 / decision N); the mirror-sync cron placement is a per-adapter
  open item.

### P/Q/R entity+geo

Reconciles this plan with decisions **P** (IPv6 hardening), **Q** (range/CIDR/ASN reputation — block
ranges, not many IPs), and **R** (country policy via LOCAL GeoIP), kept consistent with the design's
matching subsection.

- **P2/Q2 — mirror/gate matching by CIDR-containment / ASN-lookup, never exact-match.** The Config-defaults
  block gained `allowlist.asns` (containment note). Phase 2 documents `mirrorVerdict` matching by
  containment (a small pure `Net::contains`/`Net::normaliseV6` helper, `inet_pton`-based, 7.3-legal),
  normalising an IPv6 to its `/64` (or the flagged prefix) before lookup, most-specific-match-wins (Q4),
  with three new tests (`test_mirror_matches_by_cidr_containment_not_exact`,
  `test_mirror_ipv6_normalised_to_64_before_lookup`, `test_mirror_most_specific_match_wins`). Phase 5's
  allowlist step matches ips/cidrs/asns by containment (`test_allowlist_matches_asn_and_cidr_by_containment`);
  Phase 6's reputation step matches mirror + per-IP by containment/IPv6-/64/ASN
  (`test_mirror_matches_range_by_containment`). The Definition-of-done ladder + class list now name the
  `Net` helper and the containment property.
- **R — country cheap-static gate + `GeoIpInterface`.** Phase 1 declares `GeoIpInterface::country(string
  $ip)` → `?string` (local DB, no network call — R2), ships `Geo\NullGeoIp`, and adds a `FakeGeoIp` +
  `test_geoip_local_only_and_miss_returns_null`. Phase 4 adds the `country` config block (default off,
  `mode='deny'`, `action='modifier'`) + `allowlist.asns`, with `test_country_defaults_off_modifier` and
  `test_allowlist_has_asns_key`. Phase 5 (retitled "steps 1–3a") injects the GeoIp port and adds **step 3a**
  — after allowlist/pin, before reputation/content — implementing deny-list / allow-list posture ×
  modifier/deceive/block (DEFAULT modifier falls through and arms the reputation trigger; hard block /
  allow-list is opt-in; honeypot prefers score/deceive over block, R3/M6; geo miss falls through, R4), with
  five new country tests. Phase 6 folds the `countrySuspicion` flag in as an added modifier. Phase 11 adds
  `test_geoip_throw_degrades_to_allow` (the country lookup can never take the site down). Cross-piece: the
  thin adapter provides a `GeoIpInterface` over the host's shipped/refreshed local GeoIP DB (else
  `NullGeoIp`). Renumbered design cross-refs `SiteProfile` §2.6→§2.7 and the seed §2.7→§2.8 in the plan.

### S/T signals+telemetry

Reconciles this plan with decisions **S** (request-shape bot signals — individual in `core.classify()`,
composite in policy, never a standalone block) and **T** (signals ride check + report as low-trust async
telemetry, never the abuse score, never a read-path write), kept consistent with the design's matching
subsection.

- **S1 — the signal set on the `Verdict`.** Phase 1 adds **`Verdict.botSignals`** (opaque presence/
  self-consistency flags + UA class + the digit-stripped structural fingerprint token — computed in core's
  `classify()`, input-side only, never a signature string) and **`ReputationVerdict.usageType`** (F's
  `context.usage_type`, the S3 fusion input); the Phase-1 done-when + `test_value_objects_roundtrip` cover
  both. The Cross-piece funnypot-core ripple gained "compute the bot-signal set into `botSignals` +
  `anomalyScore`".
- **S2/S3/S5 — composite fusion in Phase 7.** Phase 7's `classify()` step folds `botSignals` in as a
  **composite modifier**: FP guards FIRST (allowlist/SAFE_PATHS + `bot_signals.exempt_uas`/`exempt_paths`
  zero an exempt actor's signals, S5), never-alone (a single weak signal only raises scrutiny / arms the
  reputation-escalation trigger, S2/M6), and fusion with `usageType=datacenter` + the country modifier (S3).
  Added `tests/Engine/BotSignalCompositeTest.php` (single-signal-never-acts, datacenter fusion, anomaly-only-
  never-deceives, FP-guards-zero-first, disabled-ignores). The §5 deception rule already bars deceive on
  anomaly-alone.
- **S4/T — telemetry on report + escalation-check, never the request path.** Phase 3's `ReportIntent` gains
  the `bad-bot` category (signal-weighted confidence, S4) + an opt-in **`signals`** object (T4/T5), with
  `test_report_intent_signals_opt_in_and_fingerprint_safe`. Phase 10 emits them through the suppression
  quorum and asserts the opt-in gating + fingerprint-safety (`test_bad_bot_category_and_opt_in_signals`).
  §2.2 keeps the request-path `lookup` signal-free (T3); the adapter attaches the identical `signals` object
  to F's **out-of-band escalation check + reporter** (gated by `bot_signals.telemetry`) — Cross-piece
  mainnet-client + D/E/app ripples updated. F/A1 async-queue it as low-trust enrichment/calibration, never
  the abuse score, never a read-path write (T2/T3).
- **Config.** Phase 4 adds the `bot_signals` block (`enabled=true`, `exempt_uas=[]`, `exempt_paths=[]`,
  `telemetry=false`) + `botSignals()` getter with `test_bot_signals_defaults`; the Orientation config-defaults
  block and the Definition-of-done coverage list now name it. Per-signal weights stay in `core.classify()`
  (S1) — referenced, not duplicated here.
