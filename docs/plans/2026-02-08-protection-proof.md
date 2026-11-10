# Plan: Protection proof + armed device hints + console polish

Design: docs/designs/2026-02-08-protection-proof-and-visual-upgrade.md
Working dir: /home/grey/siteguard-analytics. Single commit at the end.
Tests: `php dev/tests/run.php` (101 passing today); lint via `php -l`.

## Task 1 — Fingerprint::hits() + GROUP_PROFILE
Files: src/Core/Profile/Fingerprint.php, src/Core/Waf/Rules.php, src/Core/Waf/Inspector.php
- Rules: add `GROUP_PROFILE = 'profile'`.
- Fingerprint: `hits(array $profile): array` — map impossibles() reasons to
  `['rule'=>'fp-<reason>','group'=>'profile','severity'=>S,'evidence'=>reason]`
  via a private const map (touchless-*/desktop-screen-ios → 4;
  timezone-offset-mismatch/memory-off-scale/cores-implausible → 3;
  timezone-offset-unparseable → 1). Never throws.
- Inspector::hasProbeHit(): profile group counts as a probe hit (leave the
  scanner/anomaly exclusion untouched).
Tests (ProfileFingerprintTest): severity map incl. unknown reason → skip;
clean/empty → []; verdict() bands equal automationBands() on the 6-row corpus.

## Task 2 — Policy/Settings toggle
Files: src/Core/Settings.php, src/Core/Policy.php
- defaults += 'waf_device_hints' => true; default 'waf_profile' observe → balanced.
- sanitize: flag checkbox ('1'/1/true), plus waf_profile whitelist unchanged.
- Policy::deviceHintsEnforced(): bool; Policy::wafMode(): string (validated
  off/observe/balanced/strict, fallback observe — mirrors profile()).
Tests (SettingsTest): sanitize rounds; defaults carry both keys.

## Task 3 — People::profileFor + gate consult
Files: src/Core/Store/People.php, src/Wp/Store/WpdbPeopleStore.php,
dev/tests/SqliteStores.php, src/Core/Waf/Gate.php, src/Wp/Config.php
- People interface += profileFor(string $visitorId): array (decoded array or []).
- WpdbPeopleStore::profileFor: SELECT profile WHERE id=%s, json_decode→array|[].
  Guard non-WP test stores: SqlitePeople gains profile rows already stored by
  touchVisitor; add profileFor there too.
- Gate ctor: (mode, Policy, Incidents, Blocks, Clock, People, bool $deviceHints).
  Update Config::wafGate() (inject WpdbPeopleStore + deviceHintsEnforced()) and
  WafGateTest::make().
- REVIEWER RESOLUTIONS (2026-02-08, locked):
  1. No Installer migration: installs whose stored option predates the key get
     'balanced' via merge — that is the requested arming; README/FAQ say so.
  2. WAT matrix fits the real corpus (see Task 4 addendum below).
  3. Consult placement BEFORE the empty-hits early return and before the
     scanner drop (done). Scanner hits surviving alongside profile hits is
     accepted multi-signature behavior.
  4. One PK SELECT per returning visitor request accepted. Protection card
     gains an honest "inert" note when collection is off.
  5. Rule counts computed dynamically (count(Rules::all())); groups = 7.
  6. Gate evidence JSON gains bar_severity/bar_score going forward; old rows
     render without a bar.
  7. Harness drives /usr/bin/chromium --headless; shots to dev/tools/shots/.
- Gate::check(): after scanner drop, if flagged-on && visitorId !== '':
  merge Fingerprint::hits(profileFor(visitorId)) into $hits before score().
  Malformed stored JSON → [] (profileFor law), acts clean.
Tests (WafGateTest): second-visit denial in balanced; observe records only;
authenticated never denied; toggle off disables; no profile = pass; forged
visitor with lying profile blocks only the ip subject (assert decision.scope
== 'ip' and visitor subject has no row).

## Task 4 — WafProbe (WAT) — CORPUS-VISIBLE payloads (reviewer Q2)
Files: new src/Wp/Admin/WafProbe.php, dev/tests/WafProbeTest.php
Matrix (pass law: expected rule appears among the DECISION's fired rules AND
the per-mode outcome matches; outcomes: deny=balanced/strict, detect=observe):
| # | surface | payload (fits Rules.php anchors) | expected rule | sev | balanced outcome |
|---|---|---|---|---|---|
| 1 | query file= | `../../../etc/passwd` | rce-passwd-file | 5 | deny |
| 2 | query s= | `<script>alert(1)</script>` | xss-script-tag | 4 | deny |
| 3 | query q= | `1 union select user from wp_users` | sqli-union-select | 4 | deny |
| 4 | query cmd= | `; cat /etc/shadow` | rce-command-injection (also fires rce-passwd-file; expected among fired) | 4/5 | deny |
| 5 | path | `/wp-config.bak` | wp-config-direct | 5 | deny |
| 6 | UA + query id= | UA `sqlmap/1.8`, query `id=sleep(25)` | sqli-time-based (partner present) | 5 | deny |
| C | query | `utm_source=newsletter&colour=blue&sale=50%25 off` | none fired | – | allow |
Stamp: "6/6 stopped" only when all deny in deny-modes; in observe wording
"6/6 detected (observe)". report() returns rows + stamp + mode; cached 1h in
transient siteguard_wat_probe; Actions::saveSettings() deletes the transient.
Gate is built via Config::wafGate()-equivalent args with inert stores
implements Blocks+Incidents (countFor→0, add→id, record→noop, active→null)
plus profileFor→[] People. Verdict strings: stopped/detected-observe/detected-
below-bar (allowed but rules fired — balanced medium case)/leak/control-ok/
control-false-positive.
Tests: interpreters direct (pure), matrix shape, inertness (no rows),
expected-rule assertions against Rules::all() ids.

## Task 5 — Security/Overview/Visitors/Profiles/Settings UI
Files: src/Wp/Admin/Security.php, Overview.php, Visitors.php, Profiles.php,
SettingsPage.php, Views.php, Actions.php, Cli.php, assets/admin.css
- Views:: lamp/verdict/probe-stamp helpers + groupBadge map.
- Security: protection status card (arm-row + stats grid by design 3.1),
  WAF self-test card (WafProbe::report()), then existing cards; incidents
  table gains Class chip + Gate-evidence formatting.
- Overview: stats += WAF mode; observe-mode second notice.
- Visitors: Verdict column via Fingerprint::verdict(); detail drawer reason
  chips.
- Profiles: enforcement wording update (device hints armed).
- Settings: WAF mode select + device-hint checkbox; label copy.
- Cli::status: one WAF line.
- admin.css: --sg-info, lamp styles + pulse (reduced-motion off), verdict
  chip, probe stamp, code ellipsis, tabular-nums (additive only).

## Task 6 — Visual harness + screenshots
Files: new dev/tools/render-protection.php, dev/tools/visual-check.mjs
- WP-shim render of Security section with seeded stores → out HTML; Playwright
  chromium 1280+480 screenshots into dev/tools/shots/; assert no x-overflow.

## Task 7 — Version bump + docs + CI green
- siteguard-analytics.php 0.1.9→0.1.10 (both constants).
- README feature rows; FAQ 3 entries (Views::faq).
- php -l all; run.php all green; commit.
