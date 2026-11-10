<?php

declare(strict_types=1);

namespace SiteGuard\Tests;

use SiteGuard\Core\Profile\Fingerprint;
use SiteGuard\Core\Profile\Watchlist;
use SiteGuard\Wp\Admin\Actions;

/**
 * The watchlist entry-model and matcher laws: the anchor vocabulary is closed to
 * lie-shaped reasons (a clean profile can never become an entry), the id
 * is content not name (renaming keeps one attacker = one entry), entry
 * normalization is the single gate every stored or imported row must
 * survive, imports merge deterministically under the 200 cap, and the
 * matcher scores a stored profile only when every anchored reason re-fires
 * live AND every stored signal agrees — one hit per matching entry,
 * graded severity, warning-free on corrupt rows.
 */
final class WatchlistTest extends TestCase
{
    /** The canonical spoofed client: Mac claim, Windows statement, software renderer. */
    private const SPOOFED = [
        'platform' => 'MacIntel', 'ua_platform' => 'Windows', 'ua_mobile' => '0',
        'webgl_vendor' => 'Google Inc. (SwiftShader)',
    ];

    /**
     * Everything the built-in detectors can actually emit must stay
     * anchorable, and the compatible-overlap classes (iPadOS-Mac,
     * Android-Linux) must stay out: the vocabulary is a closed list, not a
     * pattern. Probing Fingerprint here is the independent check that the
     * model's static list never drifted from what conflicts() emits.
     */
    public function testAnchorableRulesCarryTheBuiltInLies(): void
    {
        $anchorable = Watchlist::ANCHORABLE_RULES();
        $this->assertTrue(in_array('claimed:mac-stated:windows', $anchorable, true),
            'the canonical contradiction is anchorable.');

        // one hint string per family that Fingerprint::platform resolves
        // from a single field
        $hint = ['windows' => 'Win32', 'mac' => 'MacIntel', 'ios' => 'iPhone',
            'android' => 'Android', 'chromeos' => 'Chrome OS', 'linux' => 'Linux'];
        $emitted = [];
        foreach ($hint as $claimHint) {
            foreach ($hint as $statedHint) {
                $emitted = array_merge(
                    $emitted,
                    Fingerprint::conflicts(['platform' => $claimHint, 'ua_platform' => $statedHint])
                );
            }
        }
        $emitted = array_merge(
            $emitted,
            Fingerprint::conflicts(['platform' => 'Win32', 'ua_mobile' => '1']),    // claimed:windows-stated:mobile
            Fingerprint::conflicts(['platform' => 'iPhone', 'ua_mobile' => '0']),  // claimed:ios-stated:desktop
            Fingerprint::impossibles(['platform' => 'iPhone', 'ua_mobile' => '1', 'touch' => '0']),
            Fingerprint::impossibles(['platform' => 'iPhone', 'ua_mobile' => '1', 'touch' => '5', 'screen' => '2048x1536']),
            Fingerprint::impossibles(['platform' => 'Linux x86_64', 'ua_platform' => 'Android', 'ua_mobile' => '1', 'touch' => '0']),
            Fingerprint::impossibles(['platform' => 'Win32', 'mem' => '7']),
            Fingerprint::impossibles(['platform' => 'Win32', 'cores' => '999']),
            Fingerprint::impossibles(['tz' => 'America/New_York', 'tz_offset' => '330']),
            Fingerprint::impossibles(['tz' => 'America/New_York', 'tz_offset' => 'abc']),
            Fingerprint::headlessReasons(['webgl_vendor' => 'Google Inc. (SwiftShader)']),
            Fingerprint::headlessReasons(['webgl_renderer' => 'llvmpipe (LLVM 15)'])
        );
        foreach ($emitted as $reason) {
            $this->assertTrue(in_array($reason, $anchorable, true),
                "The emitted reason {$reason} must stay anchorable.");
        }

        $this->assertCount(36, $anchorable,
            'closure is the point: 7 impossible-hint classes + 25 emitted conflict pairs + 2 fixed conflict classes + 2 renderer classes.');

        // overlaps the detectors deliberately never emit must never anchor
        $this->assertFalse(in_array('claimed:mac-stated:ios', $anchorable, true),
            'iPadOS naming Mac is honest; it can never be a watchlist anchor.');
        $this->assertFalse(in_array('claimed:android-stated:linux', $anchorable, true),
            'Android naming Linux is honest; it can never be a watchlist anchor.');
        $this->assertFalse(in_array('claimed:foo-stated:bar', $anchorable, true),
            'a plausible-looking but never-emitted pair is refuse, not anchor.');

        $renderer = array_values(array_filter($anchorable,
            static fn (string $rule): bool => str_starts_with($rule, 'software-rendering:')));
        $this->assertSame(['software-rendering:webgl_vendor', 'software-rendering:webgl_renderer'], $renderer,
            'the renderer anchor names the signal key the reason was found in.');
    }

    public function testCleanProfileProducesNoEntry(): void
    {
        $entry = Watchlist::fromProfile([
            'platform' => 'Win32', 'ua_platform' => 'Windows', 'ua_mobile' => '0',
            'webgl_vendor' => 'Google Inc. (NVIDIA)', 'webgl_renderer' => 'ANGLE (NVIDIA GeForce RTX 4060)',
        ], 'Honest desktop');
        $this->assertSame([], $entry['rules'],
            'a clean profile carries no lie-shaped reason, so nothing can be anchored from it.');
        $this->assertNull(Watchlist::normalizeEntry($entry),
            'the closed vocabulary law in action: an entry without anchorable rules is never storable.');
    }

    public function testSpoofedProfileEntryIsDeterministic(): void
    {
        // the entry's stored signals must equal what the matcher derives
        // live from the same profile (the round-trip law Task 3 depends on)
        $first = Watchlist::fromProfile(self::SPOOFED, 'Attacker A', 'rotates IPs');
        $second = Watchlist::fromProfile(self::SPOOFED, 'Attacker A', 'rotates IPs');
        $this->assertSame($first, $second,
            'same input, same entry: the model is pure, no clock inside fromProfile.');

        $this->assertSame(['claimed:mac-stated:windows', 'software-rendering:webgl_vendor'], $first['rules'],
            'the rules are the union of the detector outputs, in detector order.');
        $this->assertSame([
            'platform' => 'mac',
            'ua_platform' => 'windows',
            'webgl_vendor' => 'Google Inc. (SwiftShader)',
        ], $first['signals'],
            'each family key resolves the way conflicts() derives the pair: the platform field through Fingerprint::platform() alone (claimed side, mac), the ua_platform field alone (stated side, windows), the renderer string raw. The pair lie is claimed-vs-stated, so the two signals keep that distinction; the mobile flag is not part of this lie and is not carried.');
        $this->assertSame('Attacker A', $first['name']);
        $this->assertSame('rotates IPs', $first['notes']);
        $this->assertSame(0, $first['created'], 'created stays 0 at the model level; the admin action stamps the clock.');
        $this->assertTrue((bool) preg_match('/^[0-9a-f]{12}$/', $first['id']),
            'the id is the first 12 hex of the content hash.');
        $this->assertSame(Watchlist::entryId($first['signals'], $first['rules']), $first['id'],
            'fromProfile derives the id exactly the way entryId does.');

        // ...and the stored table equals the live-derived one on the same
        // row (restricted to the keys the anchored rules actually pin — the
        // stored side is minimal, the live table is the full domain —
        // the matcher compares stored ⊆ live, so equality on the stored
        // keys is the agreement the matcher needs)
        $live = self::liveSignalsOf(self::SPOOFED);
        foreach ($first['signals'] as $key => $stored) {
            $this->assertSame($live[$key] ?? null, $stored,
                "the live-side table derives exactly the stored value for {\$key}.");
        }
    }

    public function testEntryIdSurvivesRename(): void
    {
        $original = Watchlist::fromProfile(self::SPOOFED, 'Attacker A', 'rotates IPs');
        $renamed = Watchlist::fromProfile(self::SPOOFED, 'Different name', 'different notes');
        $this->assertSame($original['id'], $renamed['id'],
            'name and notes are deliberately not in the hash: renaming keeps one attacker = one entry.');
    }

    public function testNormalizeEntryRejects(): void
    {
        $valid = Watchlist::fromProfile(self::SPOOFED, 'Valid anchor');
        $this->assertNotNull(Watchlist::normalizeEntry($valid),
            'the model output is the normal shape: normalization accepts it.');

        // a watchlist entry is named by a human; no name, no entry
        $this->assertNull(Watchlist::normalizeEntry(self::entryWith($valid, 'name', '')));
        $this->assertNull(Watchlist::normalizeEntry(self::entryWith($valid, 'name', '   ')),
            'a whitespace-only name is no name.');
        $this->assertNull(Watchlist::normalizeEntry(self::entryWith($valid, 'name', str_repeat('a', 192))),
            'names cap at 191 characters.');
        $this->assertSame(str_repeat('a', 191), (Watchlist::normalizeEntry(
            self::entryWith($valid, 'name', str_repeat('a', 191))
        ) ?? [])['name'] ?? null, 'the cap holds at 191.');

        // rules: a list of anchorable strings, never empty, never partial
        $this->assertNull(Watchlist::normalizeEntry(self::entryWith($valid, 'rules', [])),
            'an entry anchors at least one lie-shaped reason.');
        $this->assertNull(Watchlist::normalizeEntry(self::entryWith($valid, 'rules', 'claimed:mac-stated:windows')),
            'rules must be a list, not a bare string.');
        $this->assertNull(Watchlist::normalizeEntry(self::entryWith($valid, 'rules', [5])),
            'a rule is a string, not an int.');
        $this->assertNull(Watchlist::normalizeEntry(self::entryWith($valid, 'rules', ['claimed:mac-stated:ios'])),
            'a compatible overlap is outside the vocabulary, never anchorable.');
        $this->assertNull(Watchlist::normalizeEntry(self::entryWith($valid, 'rules', ['claimed:foo-stated:bar'])),
            'a rule string outside ANCHORABLE_RULES is refused, not pattern-matched in.');
        $this->assertNull(Watchlist::normalizeEntry(self::entryWith($valid, 'rules', ['fp-touchless-ios'])),
            'the WAF rule id is not the reason string; the vocabulary stores reasons.');

        // signals: string keys and string values, no more than 7
        $this->assertNull(Watchlist::normalizeEntry(self::entryWith($valid, 'signals', ['platform' => 5])),
            'a signal value is a string.');
        $this->assertNull(Watchlist::normalizeEntry(self::entryWith($valid, 'signals', [0 => 'windows'])),
            'a signal key is a string.');
        $this->assertNull(Watchlist::normalizeEntry(self::entryWith($valid, 'signals', ['platform' => 'windows', 'junk-key' => 'x'])),
            'the signal keys are closed like the rule vocabulary: only keys Fingerprint itself interprets.');
        $this->assertNull(Watchlist::normalizeEntry(self::entryWith($valid, 'signals', ['platform' => 'windows', 'webgl_vendor' => '  '])),
            'an empty signal value is silence, never an anchor.');

        // notes cap at 1000 characters
        $this->assertNull(Watchlist::normalizeEntry(self::entryWith($valid, 'notes', str_repeat('a', 1001))));

        // created must be a present, non-negative int
        $this->assertNull(Watchlist::normalizeEntry(self::entryWith($valid, 'created', -1)), 'created cannot go backward.');
        $this->assertNull(Watchlist::normalizeEntry(self::entryWith($valid, 'created', '7')),
            'created is an int, not a numeric string.');
        $stampless = $valid;
        unset($stampless['created']);
        $this->assertNull(Watchlist::normalizeEntry($stampless),
            'the six-key shape is the entry: a row missing created is junk.');

        // not an array at all
        $this->assertNull(Watchlist::normalizeEntry(null));
        $this->assertNull(Watchlist::normalizeEntry('nonsense'));
    }

    public function testMergeImportDedupesByIdAndCaps(): void
    {
        $spoof = Watchlist::fromProfile(self::SPOOFED, 'First view of the attacker');
        $touchless = Watchlist::fromProfile(
            ['platform' => 'iPhone', 'ua_platform' => 'iOS', 'ua_mobile' => '1', 'touch' => '0'],
            'Touchless phone');
        $offscale = Watchlist::fromProfile(['platform' => 'Win32', 'ua_platform' => 'Windows', 'mem' => '7'],
            'Off-scale memory');

        // imported wins on id collision, in the current entry's position
        $renamed = Watchlist::fromProfile(self::SPOOFED, 'Second view of the attacker');
        $merged = Watchlist::mergeImport([$spoof, $touchless, $offscale], [$renamed]);
        $this->assertSame([$renamed['id'], $touchless['id'], $offscale['id']],
            array_map(static fn (array $entry): string => $entry['id'], $merged),
            'current order first, the colliding entry replaced in place.');
        $this->assertSame('Second view of the attacker', $merged[0]['name'], 'imported wins on id collision.');
        $this->assertCount(3, $merged);

        // a duplicate inside one payload collapses to one entry
        $this->assertCount(1, Watchlist::mergeImport([], [$renamed, $renamed]),
            'identical anchors imported twice collapse to one id.');

        // the 200 cap, from a flood of distinct valid entries.
        // The 200 literals here and in WpdbWatchlist::ENTRY_CAP are one law:
        // the model's cap const is private, so this flood probe is the
        // drift guard that keeps the model's cap and the adapter's mirror
        // from moving apart.
        $crowd = [];
        for ($i = 0; $i < 210; $i++) {
            $crowd[] = Watchlist::fromProfile(
                ['platform' => 'MacIntel', 'ua_platform' => 'Windows', 'webgl_renderer' => 'llvmpipe (instance ' . $i . ')'],
                'Attacker instance ' . $i);
        }
        $capped = Watchlist::mergeImport([], $crowd);
        $this->assertCount(200, $capped, 'the 200-entry cap is enforced at the model layer.');
        $this->assertSame('Attacker instance 0', $capped[0]['name']);
        $this->assertSame('Attacker instance 199', $capped[199]['name'], 'the cap keeps the first 200 in merge order.');

        // the import path the admin action runs, against hostile payloads:
        // per-entry normalization keeps only valid rows, the merge caps the list
        $hostile = [
            'garbage-row',
            ['name' => 'No rules'],
            ['name' => 'Nested signal junk', 'signals' => ['platform' => ['deep' => []]],
                'rules' => ['claimed:mac-stated:windows'], 'notes' => '', 'created' => 0],
            ['name' => 'Vocabulary escape', 'rules' => ['claimed:foo-stated:bar'],
                'signals' => ['platform' => 'windows'], 'notes' => '', 'created' => 0],
            ['name' => 'String count', 'rules' => ['claimed:mac-stated:windows'],
                'signals' => ['platform' => 'windows'], 'notes' => '', 'created' => '0'],
            $crowd[0],  // the one valid row in the pile
        ];
        $kept = [];
        foreach ($hostile as $candidate) {
            $entry = Watchlist::normalizeEntry($candidate);
            if ($entry !== null) {
                $kept[] = $entry;
            }
        }
        $this->assertSame([$crowd[0]['id']], array_map(
            static fn (array $entry): string => $entry['id'], $kept),
            'only valid entries survive normalization.');
        $final = Watchlist::mergeImport([$spoof, $touchless, $offscale], array_merge($kept, $crowd));
        $this->assertCount(200, $final, 'merging a flood keeps the cap even with current entries in place.');
        $this->assertSame('Attacker instance 0', $final[3]['name'],
            'the colliding valid row was imported (id equal), the rest appended after the current three.');
    }

    public function testExportPayloadShape(): void
    {
        $spoof = Watchlist::fromProfile(self::SPOOFED, 'Attacker');
        $touchless = Watchlist::fromProfile(
            ['platform' => 'iPhone', 'ua_platform' => 'iOS', 'ua_mobile' => '1', 'touch' => '0'],
            'Touchless phone');
        $payload = Watchlist::exportPayload([$spoof, $touchless]);

        $this->assertSame(['version', 'exported', 'entries'], array_keys($payload));
        $this->assertSame(1, $payload['version']);
        $this->assertTrue(
            (bool) preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}$/', $payload['exported']),
            'exported is an ISO8601 timestamp.');
        $this->assertSame([$spoof, $touchless], $payload['entries'],
            'entries go out unchanged; the import side re-derives ids.');
    }

    public function testExportImportRoundTrip(): void
    {
        $entries = [
            Watchlist::fromProfile(self::SPOOFED, 'Attacker', 'rotates IPs'),
            Watchlist::fromProfile(
                ['platform' => 'iPhone', 'ua_platform' => 'iOS', 'ua_mobile' => '1', 'touch' => '0'],
                'Touchless phone'),
            Watchlist::fromProfile(['platform' => 'Win32', 'ua_platform' => 'Windows', 'mem' => '7'],
                'Off-scale memory'),
        ];
        $payload = Watchlist::exportPayload($entries);
        // over the wire: the payload is JSON to and from a file
        $incoming = json_decode((string) json_encode($payload), true);
        foreach ($entries as $index => $original) {
            $entry = Watchlist::normalizeEntry($incoming['entries'][$index]);
            $this->assertNotNull($entry, 'every exported entry re-imports validly.');
            $this->assertSame($original, $entry,
                'the round trip changes nothing: the re-derived id already equals the stored one.');

            $forged = $incoming['entries'][$index];
            $forged['id'] = 'forged12345678';
            $repaired = Watchlist::normalizeEntry($forged);
            $this->assertNotNull($repaired);
            $this->assertSame($original['id'], $repaired['id'],
                'normalization recomputes the id from content; a forged id cannot survive import.');
        }
    }

    public function testWithoutRemovesExactlyTheNamedEntry(): void
    {
        $spoof = Watchlist::fromProfile(self::SPOOFED, 'Attacker');
        $touchless = Watchlist::fromProfile(
            ['platform' => 'iPhone', 'ua_platform' => 'iOS', 'ua_mobile' => '1', 'touch' => '0'],
            'Touchless phone');
        $kept = Watchlist::without([$spoof, $touchless], $spoof['id']);
        $this->assertSame([$touchless], $kept, 'the named id is gone, the survivor keeps its order and content.');
        $this->assertSame([$spoof, $touchless], Watchlist::without([$spoof, $touchless], 'missing12345678'),
            'an id that names nobody changes nothing.');
        $this->assertSame([], Watchlist::without([$spoof], $spoof['id']));
    }

    /**
     * The Task-3 matcher: rule ids map onto the WAF corpus group vocabulary
     * exactly like the built-in fingerprint hits do.
     */
    public function testGroupOfRoutesWatchlistHitsToTheProfileGroup(): void
    {
        $this->assertSame(\SiteGuard\Core\Waf\Rules::GROUP_PROFILE,
            \SiteGuard\Core\Waf\Rules::groupOf('wl-abc123def456'),
            'a wl- rule id rides the same profile group the fp- hits use.');
        $this->assertSame(\SiteGuard\Core\Waf\Rules::GROUP_PROFILE,
            \SiteGuard\Core\Waf\Rules::groupOf('fp-touchless-ios'),
            'the pre-existing fp- routing stays put.');
    }

    /**
     * The graded severity for a contradiction anchor: the deliberate,
     * owned judgment bar (3), with the profile named in the evidence.
     */
    public function testContradictionEntryScoresThree(): void
    {
        // the contradiction-only client: the entry anchors exactly that lie
        $entry = Watchlist::fromProfile(
            ['platform' => 'MacIntel', 'ua_platform' => 'Windows', 'ua_mobile' => '0'],
            'Mac-claiming Windows client');
        $this->assertSame(['claimed:mac-stated:windows'], $entry['rules'],
            'the entry under test anchors exactly the one contradiction.');
        $live = ['platform' => 'MacIntel', 'ua_platform' => 'Windows', 'ua_mobile' => '0'];
        $hits = Watchlist::hits($live, [$entry]);
        $this->assertCount(1, $hits, 'one matching entry, exactly one hit.');
        $this->assertSame('wl-' . $entry['id'], $hits[0]['rule'],
            'the rule id names the stored entry.');
        $this->assertSame(\SiteGuard\Core\Waf\Rules::GROUP_PROFILE, $hits[0]['group']);
        $this->assertSame(3, $hits[0]['severity'],
            'a contradiction anchor scores the graded watchlist bar: 3.');
        $this->assertSame(['profile' => 'Mac-claiming Windows client',
            'reasons' => ['claimed:mac-stated:windows'], 'id' => $entry['id']],
            $hits[0]['evidence'],
            'evidence is an array: the profile name, the anchored reasons, the id.');
    }

    /**
     * Impossible-device-hint anchors keep the built-in table verbatim:
     * a lie against the claimed device family is 4, junk is 1.
     */
    public function testImpossibleHintEntryKeepsItsSeverity(): void
    {
        $touchless = Watchlist::fromProfile(
            ['platform' => 'iPhone', 'ua_platform' => 'iOS', 'ua_mobile' => '1', 'touch' => '0'],
            'Touchless phone');
        $hits = Watchlist::hits(
            ['platform' => 'iPhone', 'ua_platform' => 'iOS', 'ua_mobile' => '1', 'touch' => '0'],
            [$touchless]);
        $this->assertCount(1, $hits);
        $this->assertSame('wl-' . $touchless['id'], $hits[0]['rule']);
        $this->assertSame(4, $hits[0]['severity'],
            'an impossible-hint anchor keeps Fingerprint::HIT_SEVERITY verbatim: 4.');
        $this->assertSame(['touchless-ios'], $hits[0]['evidence']['reasons'],
            'the reasons come from the live re-run of the detectors.');

        $unparseable = Watchlist::fromProfile(
            ['tz' => 'America/New_York', 'tz_offset' => 'abc'], 'Junk offset');
        $hits = Watchlist::hits(['tz' => 'America/New_York', 'tz_offset' => 'abc'], [$unparseable]);
        $this->assertCount(1, $hits);
        $this->assertSame(1, $hits[0]['severity'],
            'an unparseable offset proves junk, not a demonstrated lie: severity 1 verbatim.');
    }

    /**
     * The plan's Review Focus law: renderer/vendor strings drift in case
     * and whitespace between two pageviews of one client — still a match.
     */
    public function testRendererAnchorMatchesCaseInsensitively(): void
    {
        $base = ['webgl_vendor' => 'Google Inc. (SwiftShader)', 'webgl_renderer' => 'ANGLE (SwiftShader)'];
        $entry = Watchlist::fromProfile($base, 'Software renderer');
        $this->assertSame(['webgl_vendor', 'webgl_renderer'], array_keys($entry['signals']),
            'a renderer lie pins both WebGL strings, never a half anchor.');
        // two pageviews of one client: case and surrounding whitespace drift
        $live = ['webgl_vendor' => '  google inc. (swiftshader)  ',
            'webgl_renderer' => 'angle (SWIFTSHADER)'];
        $hits = Watchlist::hits($live, [$entry]);
        $this->assertCount(1, $hits,
            'renderer/vendor compare case- and whitespace-insensitively on trimmed values.');
        $this->assertSame(3, $hits[0]['severity'],
            'a software-renderer anchor scores the graded watchlist bar: 3.');
        $this->assertSame(['software-rendering:webgl_vendor', 'software-rendering:webgl_renderer'],
            $hits[0]['evidence']['reasons'], 'the reasons come from the live re-run.');

        // a genuinely different renderer string is a different client
        $this->assertSame([], Watchlist::hits(
            ['webgl_vendor' => 'Google Inc. (NVIDIA)', 'webgl_renderer' => 'ANGLE (NVIDIA)'],
            [$entry]));

        // Rider from Task 3's review: the OTHER side of the same law. A stored
        // row whose renderer strings kept surrounding whitespace is a
        // legitimate row (normalization refuses only whitespace-ONLY values)
        // and must still reach the live client the pageview-drift law
        // protects — the comparison trims both sides, not just the live one.
        $paddedRow = self::entryWith($entry, 'signals', [
            'webgl_vendor' => '  Google Inc. (SwiftShader)  ',
            'webgl_renderer' => "\tANGLE (SwiftShader)\t",
        ]);
        $this->assertNotNull(Watchlist::normalizeEntry($paddedRow),
            'a padded renderer value trims non-empty, so it is a valid stored row, not junk.');
        $this->assertCount(1, Watchlist::hits($base, [$paddedRow]),
            'stored-side padding trims exactly like the live side: one client, still one match.');
    }

    /**
     * The design's core match law: EVERY field the entry carries must agree
     * — no partial scoring. Both directions probed: the signals agree but a
     * rule does not re-fire, and the rules re-fire but a signal disagrees.
     */
    public function testAllFieldsMustAgree(): void
    {
        // the entry anchors a contradiction AND a renderer lie together
        $entry = Watchlist::fromProfile(self::SPOOFED, 'Full attacker');
        $this->assertSame(
            ['claimed:mac-stated:windows', 'software-rendering:webgl_vendor'], $entry['rules']);

        // the signals agree but the renderer rule does not re-fire live
        $contradictionOnly = ['platform' => 'MacIntel', 'ua_platform' => 'Windows', 'ua_mobile' => '0',
            'webgl_vendor' => 'Google Inc. (NVIDIA)', 'webgl_renderer' => 'ANGLE (NVIDIA)'];
        $this->assertSame([], Watchlist::hits($contradictionOnly, [$entry]),
            'every anchored rule must re-fire, not just the signals agree.');

        // the renderer lie re-fires but the contradiction does not: the pair
        // signal disagrees and the claimed rule does not re-fire
        $rendererOnly = ['platform' => 'Win32', 'ua_platform' => 'Windows', 'ua_mobile' => '0',
            'webgl_vendor' => 'Google Inc. (SwiftShader)', 'webgl_renderer' => 'ANGLE (SwiftShader)'];
        $this->assertSame([], Watchlist::hits($rendererOnly, [$entry]),
            'every signal must agree live, not just one lie be present.');
    }

    /**
     * One hit per matching entry, in stored entry order.
     */
    public function testTwoEntriesBothMatchEmitTwoHits(): void
    {
        $spoof = Watchlist::fromProfile(self::SPOOFED, 'Attacker A');
        $touchless = Watchlist::fromProfile(
            ['platform' => 'iPhone', 'ua_platform' => 'iOS', 'ua_mobile' => '1', 'touch' => '0'],
            'Attacker B');
        // the touchless profile cannot satisfy the spoof entry: one hit only
        $this->assertSame(['wl-' . $touchless['id']], array_map(
            static fn (array $hit): string => $hit['rule'],
            Watchlist::hits(
                ['platform' => 'iPhone', 'ua_platform' => 'iOS', 'ua_mobile' => '1', 'touch' => '0'],
                [$spoof, $touchless])),
            'only the entry whose anchors all re-fire matches.');

        // two entries anchored on overlapping views of the widened client:
        // the touchless lie plus the off-scale memory tier. One client, two
        // deliberate profiles, two hits, in entry order. (The id-collapse law
        // keeps them distinct entries because the anchor sets differ.)
        $widened = ['platform' => 'iPhone', 'ua_platform' => 'iOS', 'ua_mobile' => '1',
            'touch' => '0', 'mem' => '7'];
        $second = Watchlist::fromProfile($widened, 'Attacker A widened');
        $this->assertNotSame($touchless['id'], $second['id'],
            'different anchors, different content id: two distinct entries.');
        $hits = Watchlist::hits($widened, [$touchless, $second]);
        $this->assertCount(2, $hits, 'two matching entries emit two hits.');
        $this->assertSame(['wl-' . $touchless['id'], 'wl-' . $second['id']],
            array_map(static fn (array $hit): string => $hit['rule'], $hits),
            'hits come out in stored entry order, one per entry.');
    }

    /**
     * The corrupt-profile law: decoded-JSON junk (nested arrays, wrong
     * types) coerces to no hits with ZERO warnings under E_ALL — the
     * matcher sanitizes before the detectors ever see the row.
     */
    public function testGarbageProfileYieldsNoHits(): void
    {
        $entry = Watchlist::fromProfile(self::SPOOFED, 'Attacker');
        $garbage = [
            ['platform' => ['nested'], 'ua_platform' => 'Windows', 'ua_mobile' => '0',
                'webgl_vendor' => ['x' => 'y'], 'webgl_renderer' => 5, 'touch' => true, 'mem' => []],
            ['platform' => 'Win32', 'touch' => ['0'], 'screen' => ['1920x1080'],
                'cores' => 999, 'mem' => '7', 'tz_offset' => 330,
                'webgl_vendor' => 'Google Inc. (SwiftShader)'],
        ];
        $warnings = 0;
        set_error_handler(static function (int $no, string $msg, string $file, int $line) use (&$warnings): bool {
            $warnings++;
            return true;
        });
        error_reporting(E_ALL);
        try {
            $hits = Watchlist::hits($garbage[0], [$entry]);
            $this->assertSame([], $hits, 'nested junk reads as silence: no matches.');
            $hits = Watchlist::hits($garbage[1], [$entry]);
            $this->assertSame([], $hits,
                'the SwiftShader string cannot match a profile whose signals never agree: no hits.');
        } finally {
            restore_error_handler();
        }
        $this->assertSame(0, $warnings,
            'coercion happens inside Watchlist, before the detectors run: callers stay warning-free.');
    }

    public function testHitsAreEmptyForCleanAndEmptyLiveProfiles(): void
    {
        $entry = Watchlist::fromProfile(self::SPOOFED, 'Attacker');
        $this->assertSame([], Watchlist::hits([], [$entry]),
            'an empty live row proves nothing either way: no hits.');
        $this->assertSame([], Watchlist::hits(
            ['platform' => 'Win32', 'ua_platform' => 'Windows', 'ua_mobile' => '0',
                'webgl_vendor' => 'Google Inc. (NVIDIA)', 'webgl_renderer' => 'ANGLE (NVIDIA)'],
            [$entry]),
            'an honest desktop matches nothing.');
    }

    /**
     * The blank-form anchor gate (Task 7's consumer): the POST payload
     * carries which LIES to anchor, one item per submitted anchor
     * ['rule' => reason, 'signals' => field => fixed value]. The server
     * rebuilds the entry through fromProfile's own derivation, so the
     * assembled entry is exactly the model's — never the client's word.
     */
    public function testAnchorPostRebuildsTheAnchoredEntry(): void
    {
        // one item per checkbox, each carrying its fixed signal value
        $submitted = [
            ['rule' => 'claimed:mac-stated:windows',
                'signals' => ['platform' => 'MacIntel', 'ua_platform' => 'Windows', 'ua_mobile' => '0']],
            ['rule' => 'software-rendering:webgl_vendor',
                'signals' => ['webgl_vendor' => 'Google Inc. (SwiftShader)']],
            ['rule' => 'software-rendering:webgl_renderer',
                'signals' => ['webgl_renderer' => 'ANGLE (SwiftShader)']],
        ];
        // the merged profile the fixed values describe
        $anchored = ['platform' => 'MacIntel', 'ua_platform' => 'Windows', 'ua_mobile' => '0',
            'webgl_vendor' => 'Google Inc. (SwiftShader)', 'webgl_renderer' => 'ANGLE (SwiftShader)'];
        $entry = Actions::anchorEntry($submitted, 'Blank-form attacker', 'notes survive');
        $this->assertNotNull($entry);
        $this->assertSame(0, $entry['created'],
            'the clock stays out of the anchor gate: the caller stamps created before saving.');
        $this->assertSame('Blank-form attacker', $entry['name']);
        $this->assertSame('notes survive', $entry['notes']);
        $this->assertSame(Watchlist::fromProfile($anchored, 'Blank-form attacker', 'notes survive'), $entry,
            'the assembled entry is exactly what fromProfile derives from the anchored profile.');
        $this->assertNotNull(Watchlist::normalizeEntry($entry),
            'what the gate assembled is normal by construction.');

        $hits = Watchlist::hits($anchored, [$entry]);
        $this->assertCount(1, $hits,
            'the entry whose anchors describe a client must match that very client.');
        $this->assertSame('wl-' . $entry['id'], $hits[0]['rule']);
    }

    /**
     * The honesty law in both directions: a rule OUTSIDE the vocabulary is
     * refused outright, and an anchorable lie paired with the honest values
     * the detectors never fire on cannot re-derive, so it is refused too —
     * an honest value can never enter via POST.
     */
    public function testAnchorPostCarryingOnlyHonestValuesIsRefused(): void
    {
        // the honest overlap (iPadOS naming Mac) is not an anchorable rule
        $this->assertNull(Actions::anchorEntry(
            [['rule' => 'claimed:mac-stated:ios', 'signals' => ['platform' => 'MacIntel', 'ua_platform' => 'ioS']]],
            'Honest iPad', ''
        ), 'a pair the detectors never emit is not anchorable, whatever the POST claims.');

        // an anchorable LIE rule beside values no detector fires on: the
        // requested rule cannot re-derive from what the payload carried
        $this->assertNull(Actions::anchorEntry(
            [['rule' => 'software-rendering:webgl_vendor',
                'signals' => ['webgl_vendor' => 'Google Inc. (NVIDIA)',
                    'webgl_renderer' => 'ANGLE (NVIDIA GeForce RTX 4060)']]],
            'A lie it does not tell', ''
        ), 'an honest renderer value cannot be anchored as a software-rendering lie.');

        $this->assertNull(Actions::anchorEntry(
            [['rule' => 'claimed:foo-stated:bar', 'signals' => []]], 'Junk pair', ''),
            'a rule outside the closed vocabulary is refused outright.');
        $this->assertNull(Actions::anchorEntry([], 'No anchors', ''),
            'a submission naming no anchor refuses rather than saving an empty rule set.');
    }

    /**
     * Final-review Finding 3's pin: the save handler refuses over-long
     * notes with the honest redirect copy BEFORE re-derivation, so a direct
     * POST can no longer fall through to the misleading "No anchorable
     * reasons" refusal (the notes cap is in Watchlist's shape gate, but the
     * handler must name its own failure). The handler is WP-bound (redirect
     * + exit, no testable seam — the house boundary), so the pin is
     * source-level the way the settings-form hidden-zero pin is.
     */
    public function testSaveHandlerNamesTheNotesLimitBeforeTheAnchorGate(): void
    {
        $handler = (string) file_get_contents(SITEGUARD_DIR . 'src/Wp/Admin/Actions.php');
        $saveStart = strpos($handler, 'public static function watchlistSave');
        $saveEnd = $saveStart === false ? false : strpos($handler, 'public static function watchlistDelete');
        $this->assertTrue($saveStart !== false && $saveEnd !== false,
            'The watchlistSave handler must be extractable from Actions.php.');
        $save = (string) substr($handler, (int) $saveStart, (int) $saveEnd - (int) $saveStart);
        $this->assertTrue(str_contains($save, 'strlen($notes) > 1000'),
            'The handler guards the notes length at the model\'s byte-based cap.');
        $this->assertTrue(str_contains($save, 'Notes are limited to 1000 characters.'),
            'The refusal names the limit, never the anchor-only message.');
        $this->assertTrue(strpos($save, 'strlen($notes) > 1000') < strpos($save, 'anchorEntry'),
            'The guard runs before re-derivation, so the misleading anchor refusal is unreachable for over-long notes.');
    }

    /**
     * Ledger concern pinned here (from Task 2's review): a device-hint lie
     * depends on no Fingerprint::SIGNALS key — its postable content is the
     * hardware hint itself — so the blank form must be able to build a
     * rules-only entry, and normalizeEntry must accept the shape.
     */
    public function testBlankFormAnchorsMayBeRulesOnly(): void
    {
        $entry = Actions::anchorEntry(
            [['rule' => 'memory-off-scale', 'signals' => ['mem' => '7', 'platform' => 'Win32']]],
            'Off-scale memory', '');
        $this->assertNotNull($entry);
        $this->assertSame(['memory-off-scale'], $entry['rules']);
        $this->assertSame([], $entry['signals'],
            'a hint lie carries its evidence in the reason string, so the entry stores no signal.');
        $this->assertNotNull(Watchlist::normalizeEntry($entry),
            'rules-only entries are a valid stored shape.');
        $this->assertCount(1, Watchlist::hits(['platform' => 'Win32', 'mem' => '7'], [$entry]),
            'and the rules-only entry must still match its lie live.');
    }

    /**
     * POST junk reads as silence, not trust: signal keys outside the two
     * closed sets (Fingerprint::SIGNALS plus the hardware hints) are
     * ignored — unknown names, integer keys, array values — so nothing the
     * payload carries can smuggle itself into the stored signals. A forged
     * per-anchor id is unread: the entry id is content-derived always.
     */
    public function testAnchorPostJunkReadsAsSilence(): void
    {
        $entry = Actions::anchorEntry(
            [['rule' => 'claimed:mac-stated:windows', 'id' => 'forged12345678',
                'signals' => ['platform' => 'MacIntel', 'ua_platform' => 'Windows', 'ua_mobile' => '0',
                    'junk-key' => 'x', 'user-agent' => ['deep' => 'array'], 7 => 'integer key']]],
            'Attacker', '');
        $this->assertNotNull($entry);
        $this->assertSame(['claimed:mac-stated:windows'], $entry['rules']);
        $this->assertSame(['platform' => 'mac', 'ua_platform' => 'windows'], $entry['signals'],
            'only real signal keys contribute, and the stored value is the derived family, never the raw POST word.');
        $this->assertNotSame('forged12345678', $entry['id'],
            'the per-anchor id is unread: the entry id is the content digest.');
    }

    /**
     * Rider 1 from Task 2's review: without()'s docblock promises never
     * fatal, but the closure was typed array — junk must merely survive.
     */
    public function testWithoutToleratesNonArrayJunkRows(): void
    {
        $spoof = Watchlist::fromProfile(self::SPOOFED, 'Attacker');
        $kept = Watchlist::without(['junk-string', 42, $spoof], $spoof['id']);
        $this->assertSame(['junk-string', 42], $kept,
            'junk rows carry no entry id, so they cannot be the named id — they stay; never a fatal.');
        $kept = Watchlist::without(['junk-string', $spoof], 'missing12345678');
        $this->assertSame(['junk-string', $spoof], $kept,
            'an id that names no surviving row changes nothing — junk included.');
    }

    /**
     * Rider from Task 3's review: the entry junk gate promises depth, but a
     * row that passes every typed check while anchoring NOTHING (rules: [])
     * walks the vacuous loop — kept rules, severity 0 — and would emit a
     * phantom hit on any matching client. Unreachable from a normalized
     * store; the gate still refuses it in depth.
     */
    public function testEmptyRulesRowIsJunkNotAPhantomHit(): void
    {
        $spoof = Watchlist::fromProfile(self::SPOOFED, 'Attacker');
        // hand-shaped row: the real content id, but nothing anchored — every
        // typed check in the junk gate passes, so only the emptiness itself
        // can stand between the row and a phantom severity-0 hit
        $hollow = self::entryWith(self::entryWith($spoof, 'rules', []), 'signals', []);
        $this->assertSame([], Watchlist::hits(self::SPOOFED, [$hollow]),
            'an entry anchoring no reason is junk: it emits no hit, not even an empty one.');
    }

    /**
     * The live-side signal table the matcher is required to derive,
     * spelled out in the test exactly as the dispatch pins it: single-field
     * family resolution (claimed through the platform field alone, stated
     * through ua_platform alone, both through Fingerprint::platform),
     * ua_mobile as '0'/'1', renderer/vendor trimmed strings. Mirroring it
     * here is the independent check that the stored side and the live side
     * can never disagree by construction drift.
     * @param array<string,mixed> $profile
     * @return array<string,string>
     */
    private static function liveSignalsOf(array $profile): array
    {
        return [
            'platform' => Fingerprint::platform(['platform' => $profile['platform'] ?? '']),
            'ua_platform' => Fingerprint::platform(['ua_platform' => $profile['ua_platform'] ?? '']),
            'ua_mobile' => in_array((string) ($profile['ua_mobile'] ?? ''), ['1', 'true'], true) ? '1' : '0',
            'webgl_vendor' => trim($profile['webgl_vendor'] ?? ''),
            'webgl_renderer' => trim($profile['webgl_renderer'] ?? ''),
        ];
    }

    /**
     * @param array<string,mixed> $entry
     */
    private static function entryWith(array $entry, string $key, mixed $value): array
    {
        $entry[$key] = $value;
        return $entry;
    }
}
