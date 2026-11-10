# Design: Protection proof surfaces + armed device-hint enforcement + console polish

Date: 2026-02-08. Direction chosen: deepen the existing dark console (Option 1);
arm impossible-device-hint enforcement. Shipped plugin version goes 0.1.9 → 0.1.10.

## Problem

The protection pipeline is real (WAF gate with 46 rules over 6 groups, scored
thresholds, shared ladder and incidents; rate enforcer behind it), but:

1. The Security section shows only downstream symptoms (blocks, rate-limit
   incidents formatted as rate evidence). It has no WAF status, no rule
   inventory, no self-test. An owner cannot answer "is the WAF working?"
2. The shipped default for the WAF is `observe`, silently: the dashboard does
   not say so, so a site may be running with content signatures recording and
   never denying and only the Settings select implies it.
3. Fingerprint verdicts (hint conflicts, software renderers, impossible device
   hints) are aggregates-only in Profiles. The strongest evidence class —
   device hints that cannot all be true — is evidence-only, never enforced.
4. Visual: cards/stats/badges are functional but flat; severity and verdict
   states carry little weight; there is no "armed" visual language.

## Non-goals

- No new collector fields, no new browser signals, no schema bump (no new
  columns; settings only). SITEGUARD_TABLE_VERSION stays 2.
- No changes to tab behavior in admin.js (no tab work at all beyond nothing).
- No conflict/headless/renderer arming this pass: only `impossibles()` — the
  reasons with the strongest false-positive posture — become signatures.
  `conflicts()` and `headlessReasons()` stay evidence-only in Profiles.
- No geo, no new tables, no external calls.
- WP-CLI surface: `wp siteguard status` gains one WAF line; no new command.

## Part 1 — Arm device-hint enforcement (backend)

### Interpretation: Fingerprint::hits(array $profile): list of rule-ish hits

New pure method in `Core\Profile\Fingerprint` mapping `impossibles()` reasons
to WAF-scoring inputs. Each hit: `['rule' => 'fp-' . $reason, 'group' =>
Rules::GROUP_PROFILE, 'severity' => S, 'evidence' => $reason]`.

Severity map (false-positive posture drives it):

| reason family | severity | why |
|---|---|---|
| `touchless-ios`, `touchless-android`, `desktop-screen-ios` | 4 (high) | contradict the device family itself; real phones/tablets never report these |
| `timezone-offset-mismatch` | 3 (medium) | cross-signal lie; clock/locale oddities can rarely be legitimate |
| `memory-off-scale`, `cores-implausible` | 3 (medium) | bounded by Chromium's own enums; off-scale means tampered |
| `timezone-offset-unparseable` | 1 (low) | junk, not a demonstrated lie |

A clean or empty profile scores nothing (empty list). The method never throws
on malformed input (Fingerprint law).

### Rules: new group

`Rules::GROUP_PROFILE = 'profile'`. The group is a probe-worthy group: a
device lie IS an application-level signal, so in `Inspector::hasProbeHit()`
terms it must be treated like sqli/xss/rce/wp — Gate's probe-path law
unchanged for scanner/anomaly groups only.

### Policy + Settings toggle

- `Settings::defaults()` gains `'waf_device_hints' => true` (the user asked to
  arm it; shipped default ON for new installs).
- `Settings::sanitize()` validates it as a boolean flag same pattern as other
  checkbox keys.
- `Policy::deviceHintsEnforced(): bool` returns the flag.
- Gate constructor gains the flag (bool) — not a new store dependency yet.

### People store: profile read for the gate

- `Core\Store\People` interface gains `profileFor(string $visitorId): array`
  (decoded profile, `[]` when absent/malformed). Readers only; writes
  unchanged.
- `WpdbPeopleStore::profileFor` selects the `profile` column by primary key
  (32-char id), json_decode, array-returns. `dev/tests/SqliteStores.php`
  gains the matching SQLite implementation if absent.

### Gate integration

In `Gate::check()`, after the scanner-UA drop and before `score()`:

- When `$ctx->visitorId !== ''` AND device hints are enabled (ctor flag):
  `$profileHits = Fingerprint::hits($this->profiles->profileFor($ctx->visitorId))`
  and merge into `$hits`.
- The consult answers "has this browser lied to us before?" — the profile is
  written by the beacon of a previous pageview; a first-ever request has no
  profile and passes this layer. This is the honest cost of reading stored
  data: enforcement starts on the second visit, which is exactly when a
  returning automation client matters.
- Never consult for verified crawlers (skipped earlier), never for
  authenticated subjects (existing law: observed, not denied), off/observe
  modes behave unchanged (record, never deny).
- Constructor signature change ripples to `Config::wafGate()` (pass
  `new WpdbPeopleStore($GLOBALS['wpdb'])` + `Policy::deviceHintsEnforced()`)
  and to tests' `make()` helpers (pass a `SqlitePeople`/in-memory stub).

Never-regress laws unchanged and re-tested: visitor subjects can never be
blocks — note the profile consult is keyed by visitorId but enforcement still
blocks the `blockableSubject()` (ip/account) only; a forged visitor id adds
hits to a clean IP's request, which is a pre-existing property of content
rules (a request can carry an attack payload too) — accepted because the WAF
is per-request content scoring, and the block target is the network address.

### Severity → threshold math

Unchanged code path: device hits score like any content hit. A HIGH device lie
alone (maxSeverity 4 ≥ balanced 4) denies in balanced; in observe it records.
Score bonus applies normally (multiple simultaneous lies raise the score).

## Part 2 — WAT: the WAF acceptance test (self-probe)

New `Wp\Admin\WafProbe` mirroring `CollectorProbe` ergonomics (report() +
cached transient + plain-language interpreters), named so the dashboard can
say plainly "the WAF stopped every one of these just now".

### Mechanism

- Six documented attack payloads + one benign control — request surfaces
  (path/query/ua) that trip distinct rule groups:

  | # | surface | payload | expected rule | group | severity |
  |---|---|---|---|---|---|
  | 1 | query `file=` | `../../../etc/passwd` | rce-passwd-file | rce-lfi | critical |
  | 2 | query `s=` | `<script>alert(1)</script>` | xss-script-tag | xss | high |
  | 3 | query `q=` | `1 union select user from wp_users` | sqli-union-select | sqli | high |
  | 4 | query `cmd=` | `; cat /etc/shadow` | rce-command-injection | rce-lfi | high |
  | 5 | query `u=` | `/wp-json/wp/v2/users` | wp-users-enumeration | wp-abuse | medium |
  | 6 | UA | `sqlmap/1.8` + query `id=2-1 waitfor delay` (probe path partner so the scanner group can score) | sqli-time-based | sqli | critical |
  | C | query | `?utm_source=newsletter&colour=blue&sale=50%25 off` | none | — | — |

- Each runs through a REAL `Gate` built exactly like `Config::wafGate()`
  (same mode/policy/settings) but with **in-memory no-op stores**
  (`WafProbeStores implements Blocks, Incidents`: countFor returns 0 so the
  ladder answers with its floor rung; add() returns a row id and remembers
  nothing; record() counts only). The live incident/block tables are never
  touched — probing must not pollute the evidence the owner is reading.
- The probe reports, per payload: expected rule name, whether the decision
  crossed (denied) — in observe mode "detected, recorded (observe)" counts as
  pass — the actual rule(s) named, and a verdict string. The benign control
  passes when nothing denies on it.
- An overall stamp: "6/6 stopped (balanced, checked 12 minutes ago)."
  1-hour transient cache keyed `siteguard_wat_probe`, same TTL idea as the
  collector probe. If the WAF mode is `off`, report that instead of probing.
- `wp siteguard status` gains a `WAF: balanced (profile) / device hints on/off`
  line. No new command.

### Verdict language (plain words, tested)

- stopped: "stopped by {rule} (HTTP 429 in live traffic)"
- observe: "detected {rule}, recorded but not denying (observe mode)"
- leak: "NOT detected: the payload passed the gate — check the rules"
- benign fails: "the control request was denied — a false positive at this
  exact surface"

## Part 3 — Admin UI (console deepen)

All rendering stays server-side (no JS changes; degrade = the old page).

### 3.1 Protection card (top of Security section)

- Card 1 "Protection status": an arm-row — colored lamp + one sentence, and
  the shield state stats grid:
  - armed (balanced/strict): `--sg-ok` lamp, "Content signatures are armed:
    requests matching {N} rules are inspected and denied."
  - observe: `--sg-warn` lamp, "The WAF is watching, not blocking. Every hit
    is recorded below; flip the mode in Settings when the record looks sane."
  - off: `--sg-muted` lamp, "Content signatures are switched off."
  - emergency stop: `--sg-bad` lamp overrides everything.
  - Stats grid: `WAF mode`, `Rules` (count), `Device hints` (armed/off),
    `Incidents today`, `Active blocks`.
  - A footer line: thresholds in one sentence per mode ("balanced denies a
    single high-severity probe; strict halves the bar"). 
- Card 2 "Self-test" (WAT table): rows payload # / rule expected / verdict
  badge; stamp line + interpreter words in Evidence column. Empty/benign rows
  shown too (control row tone ok/bad).
- Card then the existing Active blocks, manual block, Recent incidents.

### 3.2 Incident table upgrade (Security)

- Columns become: When | Subject | Class | Severity | Rule | Evidence.
- Class chip derives from the rule id (Rules::groupOf + a new small
  `Views::groupBadge()`), tone map: sqli→bad, rce→bad, xss→warn, wp→warn,
  scanner→muted, anomaly→info, profile→bad, rate-limit classes→muted.
- Evidence detail: Gate evidence (`rules,max_severity,score`) formats as
  "3 signs · score 7 (bar 6)"; rate evidence keeps its existing
  "class · window · count/limit" line.

### 3.3 Overview

- Top stats grid gains `WAF mode` (ucfirst of waf_profile; a mode of observe
  also shows the existing-style warning notice appended to any present one:
  "Content protection is in observe mode: hits are recorded, not denied.").
- The Coverage matrix card stays; a last line adds the WAF probe stamp when
  fresh.

### 3.4 Visitors — verdict chips

- Recent-visitors table gains a Verdict column: `clean` (ok) / `flagged`
  (warn) / `unknown` (muted) chips built from `Fingerprint::verdict()`.
- `Fingerprint::verdict(array $profile): string` is a new tiny pure method
  (hits/conflicts/headlessReasons non-empty → flagged, profile non-empty →
  clean, else unknown); `automationBands()` refactors to call it per row (pure
  refactor; existing band laws must keep passing).
- The visitor detail drawer (existing) shows named reasons when flagged, each
  as a chip with the reason string verbatim (machine-named already).

### 3.5 Profiles

- fingerprintsCard keeps its aggregate splitBar; the enforcement statement
  updates: device-hint contradictions are now signed rules and follow the
  same ladder; conflicts/software still evidence-only, listed as such.

### 3.6 Settings

- Protection card gains: "WAF mode" select (off/observe/balanced/strict,
  default observe per current stored settings; new installs get balanced via
  defaults — wait, see decision below) and "Device-hint enforcement"
  checkbox with a one-sentence description ("Device lies no real device can
  report become denial signatures; the subject blocked is always the network
  address, never the browser id").

Mode default decision: settings default `waf_profile` changes `observe` →
`balanced` so a fresh install is defended by default (matches the user's
"arm" instruction). EXISTING installs keep their stored value because
`Settings::from()` merges stored over defaults — no silent flip; the
dashboard observe-warning makes the state loud instead.

### 3.7 CSS deepen (admin.css, additive; token names unchanged)

- Tokens: add `--sg-info` (a cool blue, distinct from warn), `--sg-lamp-*`
  derived glow colors, and radius/spacing steps already implicit made
  explicit; typography: card h3 stays, stats numbers get
  `font-variant-numeric: tabular-nums`, minor size bumps on section titles.
- New components:
  - `.sg-arm-row` + `.sg-lamp` (+ `.is-ok/.is-warn/.is-bad/.is-muted`) with a
    soft pulsing glow on the armed lamp (`prefers-reduced-motion` disables
    the pulse).
  - `.sg-verdict` chips = existing `.sg-badge` size variant.
  - `.sg-probe-stamp` (the self-test summary line).
- Table: `.sg-table td code` gets max-width + ellipsis (incident subject
  columns no longer stretch rows).

### 3.8 FAQ

- Three new entries: "What is the WAF mode?", "What does the self-test do?",
  "Why did a device-hint hit block me?"

## Part 4 — Version bump + docs

- `siteguard-analytics.php`: both version constants 0.1.9 → 0.1.10.
- README feature table: add the WAF row (46 rules, 6 groups, observe default
  note, device-hint layer) and incident-records wording covers signatures.
- FAQ entries above.
- Screenshots are NOT re-captured here (no local WP); the README header image
  stays the previous build.

## Tests

New/extended, all in `dev/tests/`:

- `ProfileFingerprintTest`: severity/group correctness of `hits()`, empty and
  clean profiles score nothing, `verdict()` bands match `automationBands()`,
  band laws unchanged.
- `WafGateTest`: device-hint hits score (balanced denies on the second
  visit's stored profile, observe records, authenticated never denied),
  the toggle disables the layer, a first-visit (no profile) passes, forged
  visitor + lying profile still blocks only the ip subject (blockableSubject
  law), malformed stored JSON acts as clean.
- `WafProbeTest`: verdicts for stopped/observe/leak/control cases; the stores
  prove no persistence; expected-rule matrix matches Rules ids; run() returns
  6 attack rows + control, all interpreted, with the mode folded in.
- `SettingsTest`: `waf_device_hints` sanitize; `waf_profile` whitelist still
  enforced.
- `CliTest`-style string assertions where the harness allows; otherwise the
  status line is covered by `WafProbeTest`'s interpreters.

CI: php -l over plugin+dev+integrations, full `php dev/tests/run.php` green,
then the visual harness, and the release build unchanged.

## Visual verification harness (dev/tools)

- `dev/tools/render-protection.php`: a ~100-line WP shim (esc_html, esc_attr,
  selected, submit_button, nocache/no-op functions) that boots
  `Settings::from([...])` with a FakeClock-equivalent time and renders
  Security::protectionRows() + WafProbe::report() (in-memory stores) into a
  static HTML file including admin.css. Output: `dev/tools/out-protection.html`.
- `dev/tools/visual-check.mjs`: Playwright (chromium already installed) loads
  the fixture, screenshots desktop (1280) and phone (480), asserts no
  horizontal overflow and the lamp/chips render; saves PNGs into
  `docs/images/` candidates (not promoted to README automatically).

## Build sequence

1. Backend arming (Part 1) + tests green.
2. WafProbe (Part 2) + tests green.
3. Admin UI (Part 3) server-rendered, lint clean.
4. Visual harness (Part "harness") + screenshots.
5. Version bump, README/FAQ, single commit, full suite + lint, CI-safe.
