# Fingerprint watchlist — design

Date: 2026-11-09
Owner request: "individual fingerprint profiles in case you can identify a single attacker", "mostly automated but a manual config page as well as major controls, especially the fingerprinting", and "the WAF may give false readings but i do want it to tie in with the profiles that are fingerprinted".

## Intent

Keep one attacker caught after they rotate IP addresses. An IP block stops the
address the gate saw; a tampered browser fingerprint stays the same across VPN
exits and mobile-network hops. The owner names and saves a fingerprint profile
(a watchlist entry) built from a real visitor the site already observed; from
then on, any visitor whose stored browser fingerprint matches the entry feeds
that match into the WAF score, so the block — when the WAF's own bar is
crossed — still lands on the network address through the existing block
ladder. The plugin drafts candidates automatically (flagged fingerprints with
recent incident history); a human always performs the act that matters:
naming and saving.

The WAF's false-positive risk is handled the way the plugin already handles
false positives everywhere else: matches are evidence, not verdicts. They have
to clear the same severity/score bar as any signature, observe mode verifies
them before enforcement, and the watchlist scoring can be switched off in
Settings without touching anything else.

## The pipeline position, in one picture

```
            today                                          new
            -----                                          ---
beacon browser signals                      beacon browser signals
        |                                           |
   Visitors row stores profile JSON          Visitors row stores profile JSON
        |                                           |
        |  Fingerprint: impossibles,                |  Fingerprint: impossibles,
        |  conflicts, headless (built-in lies)      |  conflicts, headless (built-in lies)
        |                                           |
        |                              Watchlist::hits(profile)  <-- owner-saved
        |                                           |                entries, matched
        v                                           v
   WAF Gate score  + rate limiter             WAF Gate score + rate limiter
        |
   block ladder on network address
```

Watchlist matches ride the exact score path the built-in
impossible-device-hint signatures ("fp-*") use today, so tuning, observation,
incidents, evidence, and the block ladder need no new concepts — only one new
producer of profile-group hits.

## Goals

1. **Named, saved profiles.** The Profiles section gains a Watchlist card: create
   from a stored visitor (prefilled with that visitor's signals) or from
   blank, edit, remove. Every entry is named by the owner.
2. **Export / import.** One JSON file carries all entries; import restores
   them on another install (hash ids re-derived, invalid entries rejected
   individually, never fatal).
3. **Automated candidates.** The card lists stored visitors whose fingerprint
   is flagged (contradiction, software renderer, or impossible device hints)
   and who carry WAF/incident history in the last 7 days. Saving one is one
   click into the prefilled form.
4. **WAF tie-in.** When enabled, each matching entry contributes profile-group
   signature hits through `Gate` like the built-in device-hint rules: same
   severity table, same bar, same ladder, same observe-mode behavior.
5. **Visibility.** Visitor detail shows which saved profile(s) matched; the
   watchlist card shows recent match counts per entry so the owner sees it
   working (or never firing).
6. **Major controls live in Settings**, consistent with today: a
   `Device-hint enforcement` toggle (exists), a new `Watchlist enforcement`
   toggle, and the four-mode selector. The watchlist card states plainly
   that enforcement can be verified in observe mode first.
7. **Tests.** Matcher is pure and deterministic; gate wiring stores nothing;
   export/import round-trips; import rejects malformed input; capability
   guards on every action.

## Non-goals

- No automatic rule induction from observation: nothing saves itself to the
  watchlist without a human name. This is the deliberate boundary between
  automation (drafting candidates, matching, counting) and judgment (naming,
  saving, editing).
- No per-entry deny-on-sight posture. A fingerprint is claimable by anyone;
  enforcement stays behind the WAF bar.
- No new collection. Matching uses fields the beacon already stores.
- No IP lists, no per-account lists (that is the existing "Block a client
  manually").
- No "visitor must match a profile to be allowed" mode. Honest unusual
  browsers (screen readers, hardened privacy setups, ChromeOS) must never
  need membership in a list.

## Anti-goals (what would make this a failure even if it works)

- A forged visitor id causing any enforcement. The law that a block lands on
  ip/account subjects only is unchanged; watchlist matches are scored but the
  deny path still resolves the blockable subject the Gate always has.
- Locking out real people when a saved fingerprint happens to match an
  innocent visitor who is spoofing or reusing hardware. Mitigation is the WAF
  bar plus observe-first guidance, not an extra gate we bolt on.
- Silent enforcement after upgrade: the watchlist feature is off until the
  owner turns it on (its option defaults to enabled only because an empty
  list is inert; no behavior changes until an entry exists AND the toggle is
  on).

## Constraints

- Pure interpretation of stored data only (same law as Fingerprint today).
- Settings::sanitize must know every new key; unknown keys are dropped.
- Gate constructor grows an optional last argument; every existing call site
  (Config, WafProbe with inert stores) still constructs cleanly; the default
  null store makes the feature inert when unwired.
- No new tables. Entry storage is one JSON option; tens of entries expected.
- WordPress and test adapters share the Core classes; UI never renders
  without its capability check (VIEW for reading, the manage capability for
  actions), nonces on all actions.
- The rule corpus stays immutable; watchlist entries are not corpus rules.

## Approaches considered

**Per-entry deny-on-sight vs WAF-scored vs count-only.** Deny-on-sight has
teeth the request asked for ("identify a single attacker") but would deny an
innocent visitor whose claimed fingerprint collides with a saved entry — and
the owner said the WAF may give false readings, so enforcement through the
WAF's existing bar is the compromise: real attacks crossing the bar still
block; a lone false match only files evidence. Count-only wastes the strongest
anchor we have (an owner-named profile). **Picked: WAF-scored** — the owner
confirmed it.

**Exact-vector match vs evidence-shaped match.** Comparing raw vectors
("same renderer string AND same screen AND same tz") catches same-morning
automation but the tamperer flips one field and evades forever. Matching the
lie-shaped signals instead — a platform contradiction, SwiftShader, hardware
no real device of the claimed family ships with — gives the attacker a
dilemma: lie about the same thing again and match, or tell the truth and keep
their fingerprint flagged by the built-in rules anyway. **Picked:
evidence-shaped.**

**JSON option vs a new table.** Tens of entries, owner-managed, needs export
as a first-class feature. A table adds schema, adapters, and migration for
nothing. **Picked: JSON option.**

## Decided in conversation

- Posture: matches feed the WAF score ("tie in with the profiles that are
  fingerprinted"), verified in observe mode first.
- Discovery: candidates are drafted automatically from flagged fingerprints
  with recent incident history; a human names and saves.
- Match semantics: stable, lie-shaped signals only. Entry carries the
  platform claim, stated platform, mobile claim, WebGL vendor, WebGL
  renderer, and any impossible device hints (touch, screen, cores, mem) the
  source visitor actually reported. Timezone and UA-string fields are
  excluded as match anchors (they drift legitimately: travel, upgrades).
- A match requires EVERY field the entry carries to agree — no partial
  scoring, no confidence percentages. One deliberate profile names one
  attacker.
- Storage: `siteguard_watchlist` option, JSON array of
  `{id, name, signals, rules, notes, created}`; id derived from signals so
  import cannot duplicate an identical profile under two ids; cap at 200
  entries.
- Export format: `{"version":1, "exported": <ISO8601>, "entries":[...]}`.
- Editing an entry means editing which signals it anchors; the rules map
  records each anchored field's reason class so the owner sees what a match
  means ("matches if: claims mac while stating windows, software WebGL").
- Severity (graded, owner-picked): impossible-device-hint anchors keep
  their built-in `Fingerprint::HIT_SEVERITY` values (4 for a lie against
  the claimed device family, 3 for off-scale cores/memory and timezone
  lies, 1 for a junk offset). Anchored classes the built-in table leaves
  unclassified — platform contradictions and software renderers — score 3
  for watchlist hits only: a deliberate, scoped exception to the
  evidence-only law those classes keep in the built-in corpus, justified
  because an honest browser never disagrees with itself, so an owner-named
  match on those anchors carries the judgment weight of an off-scale
  hardware claim. Net effect: an impossible-hardware match blocks alone in
  balanced (like today's built-in device-hint enforcement); a
  contradiction-only attacker blocks alone in strict mode, and in balanced
  when any other signature rides along or the match bonus tops the bar.
- Anchor vocabulary is closed to lie-shaped signals: an entry may anchor
  only reasons the built-in detectors classify — the seven impossible-hint
  reasons, the platform-contradiction classes, the software-renderer
  classes. Honest raw values (a bare GPU renderer string, a plain screen
  size) may never be anchored: create-from-visitor prefills only that
  visitor's lie reasons, create-from-blank offers the same vocabulary.
  A watchlist match therefore always implies the matched browser already
  looks dishonest to the built-in rules.
- Hit granularity: one matching entry emits exactly one rule hit, id
  `wl-{entryId}`, evidence carrying the profile name and every anchored
  reason, so incidents name the entry and score math stays per-entry.
- Capabilities: save/edit/remove/import run under `sg_manage_blocks` (the
  enforcement-adjacent capability Security's actions already require);
  export runs under `sg_export_data`, like the plugin's other exports;
  reading the card and candidates needs only `sg_view_analytics`. Every
  action is nonce-checked (house pattern).
- Candidate drafting depends on ip attribution: it works under ip_storage
  `full` (direct subject compare) and `hashed` (hash-compare against recent
  incident subjects) alike; under ip_storage `none` the candidates area
  explains the gap in one sentence instead of silently showing nothing.
- Match counts are a live replay of the matcher over the visitors present
  in the current 30-day window — the population the Profiles section
  already reports — counted per entry, always including observe-mode and
  below-bar matches: they count matches, not blocks; enforcement outcomes
  stay visible in incidents.
- The Settings page carries the `waf_watchlist` toggle next to
  `waf_device_hints`.

## What the builder decides

- Exact Match implementation shape (a new pure class in Core, suggested
  location `Core/Profile/Watchlist.php`, plus a tiny read/write store in
  Core/Store or straight option access — builder's call, keep both pure).
- Rule ids and evidence strings for watchlist hits (prefix `wl-`, entry id in
  the id, profile name in the evidence so incidents are readable).
- Candidate query details (window, incident source — WAF incidents vs rate
  limiter incidents or both), display thresholds.
- UI: exact card layout within the Profiles section, the create-from-visitor
  flow (the
  visitor detail page probably gains a "Save as watchlist profile" button,
  matching the existing "block this client" pattern in Security).
- UI copy, CSS.
- Import UX details (file upload vs paste) — follow the existing SettingsPage
  interaction patterns.
- Test fixtures and edge cases beyond the required laws (empty profile,
  entry with one signal, duplicated import, hash collision).

## Hard requirements every implementation must satisfy

- A watchlist entry can never cause a block by itself; only the Gate bar,
  exactly as scored today, denies.
- Entry storage never contains anything the plugin did not already know: no
  UA hashes of new surfaces, no IP, no personal data; entries carry only
  fingerprint fields and a human name.
- Every action (save/edit/remove/import/export) requires a manage capability
  and a valid nonce.
- Observe mode must show watchlist matches in incidents/evidence while
  denying nothing.
- With the toggle off, the matcher must not run (no score contribution, no
  incidents).
- Turning the toggle off or removing an entry stops enforcement immediately
  on the next request (no caching of decisions beyond what Config already
  does per-request).

## Verification

- New unit tests for the matcher and the export/import round trip.
- Gate-level tests: watchlist hit only when profile matches and the toggle is
  on; subject remains ip/account in any deny; observe mode records.
- A WafProbe-style live self-test remains green with the new constructor
  argument (inert store).
- The full suite (125 passing today) stays green.

Verified 2026-11-10 on branch `fingerprint-watchlist` (commits 2ba5a1d..876b0e3):
42 tests added (final suite 162 passing, 1358 assertions), all hard
requirements pinned per the cross-check table in the build's verification
report; screenshot sweep skipped honestly (~250-line harness gap — noted for
the next pass). The automated-candidates goal surfaced one end-to-end seam
( `visitors.ip_hash` existed only in the test shim) fixed with schema,
write-path, migration bump, and parity pins.
