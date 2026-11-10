<?php

declare(strict_types=1);

namespace SiteGuard\Tests;

use SiteGuard\Core\Profile\Fingerprint;
use SiteGuard\Core\Profile\Watchlist;

/**
 * The watchlist entry-model laws: the anchor vocabulary is closed to
 * lie-shaped reasons (a clean profile can never become an entry), the id
 * is content not name (renaming keeps one attacker = one entry), entry
 * normalization is the single gate every stored or imported row must
 * survive, and imports merge deterministically under the 200 cap.
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

        // the 200 cap, from a flood of distinct valid entries
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
     * @param array<string,mixed> $entry
     */
    private static function entryWith(array $entry, string $key, mixed $value): array
    {
        $entry[$key] = $value;
        return $entry;
    }
}
