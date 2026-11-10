# Fingerprint Watchlist Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Owner-named, saved, exportable fingerprint profiles (the watchlist) that feed the existing WAF score as graded profile-group signatures, with automated candidate drafting.

**Architecture:** One new pure class (`Core/Profile/Watchlist.php`) derives entries from a flagged visitor's stored signals, matches them against live stored profiles, and emits `wl-{id}` hits with graded severities. A new `Core/Store/Watchlist` interface (option-backed `WpdbWatchlist`, SQLite-backed test adapter) feeds the `Gate` as an optional 8th constructor collaborator. Admin UI: a Watchlist card in the Profiles section, a "save as watchlist profile" flow on visitor detail, and a `waf_watchlist` toggle in Settings — all following the existing capability/nonce/audit house pattern.

**Tech Stack:** PHP 8.1+ (strict_types throughout), WordPress option API, the plain `dev/tests/run.php` runner (no PHPUnit), SQLite test stores.

**Spec:** `docs/designs/2026-11-09-fingerprint-watchlist-design.md` — the plan argues from it; executors read both.

## Global Constraints

- Pure interpretation of already-stored data only; nothing new is collected.
- No new tables; entries live in the `siteguard_watchlist` option as a JSON array; cap 200 entries.
- A watchlist entry can never cause a block by itself; only the existing Gate bar denies, and the block still lands on the ip/account subject, never a visitor id.
- Anchor vocabulary is closed: only lie-shaped reasons the built-in detectors classify (`Fingerprint::impossibles()` reasons, `conflicts()` classes, `headlessReasons()` classes). Honest raw values may never be anchored.
- Graded severities: contradiction and software-renderer anchors score 3; impossible-hint anchors reuse `Fingerprint::HIT_SEVERITY` verbatim (4/3/1).
- One matching entry emits exactly one hit: rule id `wl-{entryId}`, evidence `['profile' => name, 'reasons' => anchored rules, 'id' => entryId]`.
- Capabilities: save/edit/remove/import → `Caps::MANAGE_BLOCKS`; export → `Caps::EXPORT_DATA`; card read → `Caps::VIEW_ANALYTICS`; every action nonce-checked with the four written-out steps (cap, nonce, validate, act/audit/redirect).
- Toggle-off or store-absent must make the feature completely inert (no matcher runs, no hits, no incidents).
- Tests use the existing runner (`php dev/tests/run.php`, green before work starts); no `get_option` polyfill exists — unit tests exercise pure classes directly; stores get SQLite adapters like `SqlitePeople`.
- House style: `declare(strict_types=1)`; `final` classes; docblocks explaining the why; one option row per config blob with `Settings::sanitize` knowing every key.

## Review Focus

- Corrupt or missing profile JSON on a visitor row while entries are armed — must parse to no hits, never fatal. *(Pinned: WatchlistTest garbage-profile assertion, Task 3.)*
- `webgl` vendor/renderer strings with differing case or surrounding whitespace between two pageviews of one client — must still match a renderer-anchored entry. *(Pinned: WatchlistTest case-insensitive renderer equality, Task 3.)*
- Import payload with nested arrays, missing keys, string counts, or 1000 entries — must keep only valid entries, cap at 200, never fatal. *(Pinned: WatchlistTest import adversarial cases, Task 2.)*
- A severity-1 anchor alone (junk timezone offset) — must never reach the balanced bar by itself and must never deny. *(Pinned: GateTest below-bar assertion, Task 4.)*
- Stale whole-option writes (two admins editing) — accepted as last-write-wins by design; the guard is that every store path normalizes and caps the list it writes, so a stale save can never inject an invalid entry. *(Pinned: WatchlistTest normalize/cap assertions over save-shaped input, Task 2.)*

---

### Task 1: Settings and Policy carry the watchlist knobs

**Files:**
- Modify: `plugin/siteguard-analytics/src/Core/Settings.php` (defaults array + `sanitize()`)
- Modify: `plugin/siteguard-analytics/src/Core/Policy.php`
- Test: `dev/tests/SettingsTest.php`, `dev/tests/PolicyTest.php`

**Interfaces:**
- Consumes: existing `Settings::defaults/sanitize/from`, existing `Policy` constructor.
- Produces: default key `'waf_watchlist' => true` (bool); `sanitize` accepts `'waf_watchlist'` bool-cast like `'waf_device_hints'` (no validation errors — bool cast only); `Policy::watchlistEnforced(): bool` reading `settings['waf_watchlist'] ?? true`.

- [ ] **Step 1: Write the failing tests** — SettingsTest: `defaultsCarryWatchlistToggle` (`Settings::from([])['waf_watchlist'] === true`), `sanitizeCastsWatchlistToggle` (`sanitize(['waf_watchlist' => '0'])` → false, `'1'` → true). PolicyTest: `watchlistEnforcedReadsSetting` (default true; false when the setting is false; true when the value is garbage).
- [ ] **Step 2: Run** `php dev/tests/run.php` — expect the new tests to fail on the missing key/method.
- [ ] **Step 3: Implement** both one-liners next to their `waf_device_hints` siblings, with a docblock noting the law: default-armed but inert until an entry exists and the store is wired.
- [ ] **Step 4: Run** the suite — all green.
- [ ] **Step 5: Commit** `git add plugin/.../Core/Settings.php plugin/.../Core/Policy.php dev/tests/SettingsTest.php dev/tests/PolicyTest.php && git commit -m "feat(watchlist): settings and policy knobs for watchlist enforcement"`

### Task 2: Entry model, id derivation, import/export, store interface

**Files:**
- Create: `plugin/siteguard-analytics/src/Core/Profile/Watchlist.php`
- Create: `plugin/siteguard-analytics/src/Core/Store/Watchlist.php` (interface: `all(): list<array>`, `save(list<array> $entries): void`)
- Test: `dev/tests/WatchlistTest.php` (new)

**Interfaces (all consumed by Tasks 3–7):**
- `Watchlist::ANCHORABLE_RULES(): list<string>` — the closed reason vocabulary: the 7 keys of `Fingerprint::HIT_SEVERITY` verbatim, plus the three conflict classes the built-in detector emits (`claimed:*-stated:*`), plus `'software-rendering:webgl_vendor'`, `'software-rendering:webgl_renderer'`.
- `Watchlist::fromProfile(array $profile, string $name, string $notes = ''): array` — returns `{id, name, signals, rules, notes, created}` where `rules` = union of `Fingerprint::impossibles($profile)`, `conflicts($profile)`, `headlessReasons($profile)` (lie reasons only, by construction); `signals` = normalized values for the keys those rules depend on (`platform`/`ua_platform` as `Fingerprint::platform()` output, `ua_mobile` as `'0'/'1'`, renderer/vendor raw strings) — no IP, no new surfaces; `created` = 0 at model level.
- `Watchlist::entryId(array $signals, array $rules): string` — first 12 hex of `sha256(sorted(rules) . "\n" . sorted(signals))`. Name is deliberately NOT in the hash: renaming keeps the id (one attacker = one entry), and identical anchors imported twice collapse to one id.
- `Watchlist::normalizeEntry(mixed $raw): ?array` — valid shape only: name non-empty ≤191 chars, `rules` a non-empty list ⊆ ANCHORABLE_RULES, `signals` string-keyed string values (≤7 keys), notes ≤1000 chars, created int ≥0; recomputes the id from content; null otherwise.
- `Watchlist::mergeImport(array $current, array $imported): array` — dedupe by id (imported wins), current order first then new, cap 200.
- `Watchlist::without(array $entries, string $id): list<array>` — remove by id.
- `Watchlist::exportPayload(array $entries): array` — `{version: 1, exported: <gmdate ISO8601>, entries: [...]}`.
- `Watchlist::hits(array $profile, list<array> $entries): list<array{rule:string,group:string,severity:int,evidence:array}>` — same return shape `Fingerprint::hits` uses. Tests in Task 3; in this task the body returns `[]`.

- [ ] **Step 1: Write the failing tests** (`WatchlistTest`): `cleanProfileProducesNoEntry` (fromProfile on a clean profile yields `rules === []`, and `normalizeEntry` refuses it → null — the closed vocabulary law in action); `spoofedProfileEntryIsDeterministic` (same spoofed input twice → identical id, signals, rules); `entryIdSurvivesRename` (same signals/rules, different names → same id); `normalizeEntryRejects` (empty name; a rule string outside ANCHORABLE_RULES; rules empty; oversized name); `mergeImportDedupesByIdAndCaps` (200-cap enforced, imported wins on id collision); `exportPayloadShape` (version int 1, exported is an ISO8601 string); `exportImportRoundTrip` (every exported entry survives normalizeEntry unchanged apart from the re-derived id).
- [ ] **Step 2: Run** `php dev/tests/run.php` — new tests fail (class missing).
- [ ] **Step 3: Implement** `Core/Profile/Watchlist.php` per the signatures; docblocks carry the why (closed vocabulary law, id-dedupe law, name-not-in-id).
- [ ] **Step 4: Run** — green, including the pre-existing 125.
- [ ] **Step 5: Commit** the three files.

### Task 3: The matcher — graded severities, all-fields-agree

**Files:**
- Modify: `plugin/siteguard-analytics/src/Core/Profile/Watchlist.php` (implement `hits()`)
- Modify: `plugin/siteguard-analytics/src/Core/Waf/Rules.php` — `groupOf()` gains one line next to the `fp-` case: ids starting `wl-` answer `GROUP_PROFILE`.
- Test: `dev/tests/WatchlistTest.php`

**Interfaces:**
- Consumes: `Fingerprint::impossibles/conflicts/headlessReasons/HIT_SEVERITY`, `Fingerprint::platform`.
- Produces: `Watchlist::hits()` full behavior — an entry matches only when EVERY anchored rule's reason appears in the live profile's merged reason set AND every non-empty signal key equals the live profile's normalized value (family keys compared through `Fingerprint::platform()`/`ua_mobile` normalization; renderer/vendor case-insensitively on trimmed values). Each matching entry emits one hit `{rule: 'wl-{id}', group: Rules::GROUP_PROFILE, severity: <graded>, evidence: ['profile' => name, 'reasons' => rules, 'id' => id]}`. Grading: conflict and renderer reasons → 3; impossible-hint reasons → `Fingerprint::HIT_SEVERITY` verbatim; nothing else is possible (normalized entries only). Corrupt live profiles (`$profile` values of wrong types, string offsets, partial arrays) produce no hits and no warnings.

- [ ] **Step 1: Write the failing tests** — `contradictionEntryScoresThree` (spoofed profile `platform:'MacIntel', ua_platform:'Windows'` matched by an entry anchoring that → severity 3, rule `wl-…`, name in evidence); `impossibleHintEntryKeepsItsSeverity` (touchless-ios entry → 4; timezone-offset-unparseable entry → 1); `rendererAnchorMatchesCaseInsensitively` (entry stores 'SwiftShader' as reported, live profile reports lowercase/whitespace variant → still one hit); `allFieldsMustAgree` (entry anchors a contradiction plus a renderer; live profile shows only the contradiction → no hit); `twoEntriesBothMatchEmitTwoHits`; `garbageProfileYieldsNoHits` (malformed shapes run with `error_reporting(E_ALL)` → `[]` and no notices).
- [ ] **Step 2: Run** — fail (body is the `[]` placeholder from Task 2).
- [ ] **Step 3: Implement** the matcher per the Produces spec.
- [ ] **Step 4: Run** — full suite green.
- [ ] **Step 5: Commit.**

### Task 4: Gate scores watchlist hits

**Files:**
- Modify: `plugin/siteguard-analytics/src/Core/Waf/Gate.php` — constructor gains an optional 8th param `?Store\Watchlist $watchlist = null` (alias the profile-logic class where the two `Watchlist` names collide); in `check()`, immediately after the device-hints merge: when `watchlist !== null && $this->policy->watchlistEnforced() && $ctx->visitorId !== ''`, merge `WatchlistLogic::hits($this->profiles->profileFor($ctx->visitorId), $this->watchlist->all())` into `$hits`. No other Gate line changes.
- Test: `dev/tests/WafGateTest.php`; test adapter `SqliteWatchlist implements Store\Watchlist` in `dev/tests/SqliteStores.php` (pdo-backed `siteguard_watchlist`-shaped table + a `setEntries()` helper, same style as `SqlitePeople::setProfile`).

**Interfaces:**
- Consumes: Task 2/3 signatures, `Policy::watchlistEnforced()`, Task 1 setting.
- Produces: the optional param — Config wires the real store in Task 6; WafProbe and every existing call site keep compiling unchanged because the param defaults to null. All existing score laws untouched.

- [ ] **Step 1: Write the failing tests** (thread the new store through the existing `make(mode)` harness): `matchedImpossibleAnchorDeniesThroughLadder` (balanced + severity-4 impossible anchor → deny with a `waf_signature` block on the `ip:` subject, block row rule id `wl-…`); `contradictionOnlyEntryObservesInBalanced` (severity 3 below the balanced bar → `Decision::observe`, incident recorded with the `wl-…` rule, evidence names the profile); `contradictionOnlyEntryDeniesInStrict` (strict max-severity 3 → deny); `observeModeNeverDenies` (mode observe → observed, no block row); `toggleOffMeansNoHits` (settings `waf_watchlist=false` → no incident, no block, plain allow); `severityOneNeverAloneDenies` (balanced + junk-offset anchor only → allow with `'waf' => 'below_threshold'` evidence); `forgedVisitorIdNeverBlocks` (matching profile loaded for a visitor id whose subject is not blockable → no block row with a visitor subject; the deny path resolves exactly as the existing laws do).
- [ ] **Step 2: Run** — fail (no integration).
- [ ] **Step 3: Implement** the Gate change per above.
- [ ] **Step 4: Run** — full suite green.
- [ ] **Step 5: Commit.**

### Task 5: WordPress store adapter

**Files:**
- Create: `plugin/siteguard-analytics/src/Wp/Store/WpdbWatchlist.php`

**Interfaces:**
- Consumes: `Store\Watchlist` interface, `Watchlist::normalizeEntry`, the 200 cap.
- Produces: `WpdbWatchlist implements Store\Watchlist` — option-backed only (no wpdb queries): `all()` decodes `(array) get_option('siteguard_watchlist', [])` and runs each row through `normalizeEntry`, dropping invalid rows; `save()` runs each entry through `normalizeEntry`, caps at 200 via `array_slice`, and `update_option`s the JSON list. Every store path therefore normalizes before writing — the stale-save guard from Review Focus.

No unit test for the adapter itself: it is a thin option wrapper, per the precedent of the whole `Wp/Store` layer; its correctness is pinned by the pure layer's tests.

- [ ] **Step 1: Implement** the adapter per above.
- [ ] **Step 2: Verify** `php -l` parses, full suite still green.
- [ ] **Step 3: Commit.**

### Task 6: Config wiring, admin actions, audit

**Files:**
- Modify: `plugin/siteguard-analytics/src/Wp/Config.php::wafGate()` — pass `new WpdbWatchlist()` as the 8th argument.
- Modify: `plugin/siteguard-analytics/src/Wp/Admin/Actions.php` — boot registrations + four handlers, each the written-out four steps (cap, nonce, validate, act/audit/redirect):
  - `watchlistSave` — cap `MANAGE_BLOCKS`, nonce `siteguard_watchlist_save`, redirect `Menu::PROFILES`. Input: `name`, `notes`, and anchors from either `visitor_id` (→ `People::profileFor` → `Watchlist::fromProfile`) or a blank-form anchor payload (individual anchor checkboxes with their fixed signal values; the server re-validates every submitted anchor against `ANCHORABLE_RULES`, so an honest value can never enter via POST). Save is an upsert by content id: remove any existing entry with the same id, insert the new entry, save. Audit `watchlist.saved` with id + name.
  - `watchlistDelete` — cap + nonce `siteguard_watchlist_delete`; `id` → `Watchlist::without($store->all(), $id)` → save. Audit `watchlist.removed`.
  - `watchlistImport` — cap + nonce `siteguard_watchlist_import`; payload from an uploaded file (`$_FILES['file']['tmp_name']`, capped 256 KB) or a pasted `payload` textarea; `json_decode` → `entries` array → per-entry `normalizeEntry` → `Watchlist::mergeImport($store->all(), …)` → save. Invalid entries are dropped with a count in the notice, never fatal. Audit `watchlist.imported` with kept/dropped counts.
  - `watchlistExport` — cap `EXPORT_DATA`, nonce `siteguard_watchlist_export`; stream `Watchlist::exportPayload($store->all())` with JSON attachment headers. Audit `watchlist.exported`.
- Each handler audits through the same `WpdbAuditStore` pattern `Actions::audit()` already uses.

**Interfaces:**
- Consumes: Tasks 2, 3, 5.
- Produces: working server side; UI forms come in Task 7.

- [ ] **Step 1: Implement** Config wiring + the four handlers per above.
- [ ] **Step 2: Verify** all four handler registrations exist in `boot()`, `php -l` parses each file, full suite green.
- [ ] **Step 3: Commit.**

### Task 7: Admin UI — watchlist card, candidates card, visitor save flow, settings toggle

**Files:**
- Modify: `plugin/siteguard-analytics/src/Wp/Admin/Profiles.php` — new `watchlistCard()` + `candidatesCard()`, called right after the fingerprints card.
- Modify: `plugin/siteguard-analytics/src/Wp/Admin/Visitors.php` — in `detail()`'s profile block: matched entries rendered as badge lines (entry id appears in `Watchlist::hits($profile, $entries)` rule ids → name badge), and a cap-gated `MANAGE_BLOCKS` form "Save as watchlist profile" posting `visitor_id` + editable `name`/`notes` (nonce `siteguard_watchlist_save`).
- Modify: `plugin/siteguard-analytics/src/Wp/Admin/SettingsPage.php` — a checkbox row `waf_watchlist` beside `waf_device_hints`, description telling the owner to verify with the WAF in Observe first.
- Modify: `plugin/siteguard-analytics/src/Wp/Admin/Security.php` — protection-status card gains one status line: watchlist armed (entry count) or off, reading the same settings the Gate reads.
- Modify: `plugin/siteguard-analytics/assets/admin.css` — only classes the cards need that do not already exist (~20 lines max).

**Interfaces:**
- Consumes: Tasks 2/3/6; `Views::openCard/table/badge`, `Menu::redirect` anchors (`Menu::PROFILES`), `Caps::userCan` guards on every element.

**Card contents:**
- Watchlist card (`VIEW_ANALYTICS` to read): entries table [Name · Anchored rules (human phrasing, e.g. "claims mac while stating windows") · Matches 30d · Created · Edit · Delete · Export], counts computed by replaying `Watchlist::hits` over the visitors in the existing 30-day window; Edit pre-fills the same form Delete uses; all action forms inline like `liftButton`. Below the table: the create-from-blank form (name, notes, anchor vocabulary as checkboxes, each carrying its fixed value) and the import form (paste textarea + file input), each `MANAGE_BLOCKS`-gated; Export link `EXPORT_DATA`-gated.
- Candidates card: visitors in the 30-day window whose decoded profile is flag-worthy AND whose ip carried incident history in the last 7 days — attribution mode: `full` → direct subject compare; `hashed` → hash-compare recent incident subjects against visitor ip_hash; `none` → one-sentence explanation, no list. Each row: visitor link, last seen, lie reasons, [Save as watchlist profile…] (pre-fills the entry form via `visitor_id`), [Discard] (per-browser transient only — never persisted).

- [ ] **Step 1: Implement** both cards in Profiles.php and the visitor-detail affordance per the card contents above; every render behind its cap check; every string esc_html'd, URL esc_url'd, form nonced.
- [ ] **Step 2: Implement** the SettingsPage toggle and the Security status line.
- [ ] **Step 3: Verify** via a render smoke (`dev/tools/render-protection.php` or the existing tooling): no PHP warnings, sections render; full suite green.
- [ ] **Step 4: Commit.**

### Task 8: Whole-feature verification

No source changes expected; verification only.

- [ ] **Step 1: Full suite** `php dev/tests/run.php` — all green, including the pre-existing 125 plus every new Watchlist/Settings/Policy/Gate test.
- [ ] **Step 2: Design cross-check:** walk each Hard requirement and anti-goal in the spec; name the test or task step that pins each.
- [ ] **Step 3: Screenshots** of the new cards via `dev/tools/shot.mjs` at 390px and desktop widths: the watchlist card, the candidates card, the visitor-detail badges, the Settings toggle. No overflow, readable copy.
- [ ] **Step 4: Report** verification outputs verbatim to the owner.

---

## Explicitly out of scope

- WafProbe matrix rows for watchlist entries (the self-test probes the shipped corpus, not owner data).
- Per-entry scheduling, per-entry modes, deny-on-sight, IP/account lists.
- Any persistence for candidate Discards.
