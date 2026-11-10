<?php
declare(strict_types=1);

namespace SiteGuard\Tests;

use SiteGuard\Core\Profile\Fingerprint;

/**
 * The fingerprint laws: a profile resolves to exactly one platform family
 * (including the real-world phrasing overlaps), tampered clients disagree
 * with themselves, software renderers name the headless browser, and junk
 * input lands in 'unknown' instead of throwing.
 */
final class ProfileFingerprintTest extends TestCase
{
    public function testPlatformMappingReadsBothHintsTogether(): void
    {
        // the honest ways real browsers phrase the same facts
        $this->assertSame('windows', Fingerprint::platform(['platform' => 'Win32', 'ua_platform' => 'Windows']));
        $this->assertSame('mac', Fingerprint::platform(['platform' => 'MacIntel', 'ua_platform' => 'macOS']));
        $this->assertSame('ios', Fingerprint::platform(['platform' => 'iPhone', 'ua_platform' => 'iOS', 'ua_mobile' => '1']));
        $this->assertSame('android', Fingerprint::platform(['platform' => 'Linux x86_64', 'ua_platform' => 'Android', 'ua_mobile' => '1']), 'Android Chrome reports Linux as its platform hint.');
        $this->assertSame('chromeos', Fingerprint::platform(['platform' => '', 'ua_platform' => 'Chrome OS']));

        // iPadOS reports MacIntel while UA-CH still says iOS
        $this->assertSame('ios', Fingerprint::platform(['platform' => 'MacIntel', 'ua_platform' => 'iOS', 'ua_mobile' => '1']), 'an iPad is mobile even though its platform hint says Mac.');
        $this->assertSame('ios', Fingerprint::platform(['platform' => 'MacIntel', 'ua_mobile' => '1']), 'a mobile Mac claim is the iPad case.');

        // junk and silence land in the catch-all families, never throw
        $this->assertSame('unknown', Fingerprint::platform(['platform' => '']));
        $this->assertSame('other', Fingerprint::platform(['platform' => 'RISC OS']));
    }

    public function testPlatformBandsAssignEveryProfileExactlyOneFamily(): void
    {
        $bands = Fingerprint::platformBands([
            ['platform' => 'Win32', 'ua_platform' => 'Windows'],
            ['platform' => 'Win32', 'ua_platform' => 'Windows'],
            ['platform' => 'MacIntel', 'ua_platform' => 'macOS'],
            ['platform' => 'iPhone', 'ua_platform' => 'iOS', 'ua_mobile' => '1'],
            ['platform' => 'Linux x86_64', 'ua_platform' => 'Android', 'ua_mobile' => '1'],
            ['platform' => 'Linux x86_64'],
            [],
            'malformed-row',
        ]);
        $this->assertSame(2, $bands['windows']);
        $this->assertSame(1, $bands['mac']);
        $this->assertSame(1, $bands['ios']);
        $this->assertSame(1, $bands['android']);
        $this->assertSame(1, $bands['linux']);
        $this->assertSame(2, $bands['unknown'], 'an empty profile and a malformed row both land in unknown.');
        $sum = array_sum($bands);
        $this->assertSame(8, $sum, 'one profile in, exactly one band out.');
        foreach (Fingerprint::PLATFORMS as $family) {
            $this->assertTrue(array_key_exists($family, $bands), 'every declared family is present in the band table.');
        }
    }

    public function testConflictsCatchSelfDisagreementNotRealOverlaps(): void
    {
        // the honest clients: hints agree, or the overlap is a real one
        $this->assertSame([], Fingerprint::conflicts(['platform' => 'Win32', 'ua_platform' => 'Windows', 'ua_mobile' => '0']));
        $this->assertSame([], Fingerprint::conflicts(['platform' => 'MacIntel', 'ua_platform' => 'macOS', 'ua_mobile' => '0']));
        $this->assertSame([], Fingerprint::conflicts(['platform' => 'Linux x86_64', 'ua_platform' => 'Android', 'ua_mobile' => '1']), 'Android naming Linux is not a conflict.');
        $this->assertSame([], Fingerprint::conflicts(['platform' => 'MacIntel', 'ua_platform' => 'iOS', 'ua_mobile' => '1']), 'iPadOS naming Mac is not a conflict.');
        // a lone hint cannot disagree with itself
        $this->assertSame([], Fingerprint::conflicts(['platform' => 'Win32']));

        // the tampered clients: one hint edited, the other left honest
        $this->assertSame(['claimed:mac-stated:windows'], Fingerprint::conflicts(['platform' => 'MacIntel', 'ua_platform' => 'Windows']), 'a Mac claim with a Windows statement is a contradiction.');
        $this->assertSame(['claimed:windows-stated:mac'], Fingerprint::conflicts(['platform' => 'Win32', 'ua_platform' => 'macOS']));
        $this->assertSame(['claimed:windows-stated:mobile'], Fingerprint::conflicts(['platform' => 'Win32', 'ua_mobile' => '1']), 'a desktop platform hint claiming to be mobile is a contradiction.');
        $this->assertSame(['claimed:ios-stated:desktop'], Fingerprint::conflicts(['platform' => 'iPhone', 'ua_mobile' => '0']), 'an iPhone platform hint claiming to be desktop is a contradiction.');
        // junk input yields no conflict either way
        $this->assertSame([], Fingerprint::conflicts([]));
    }

    public function testHeadlessReasonsNameTheSoftwareRenderer(): void
    {
        $this->assertSame(['software-rendering:webgl_vendor'],
            Fingerprint::headlessReasons(['webgl_vendor' => 'Google Inc. (SwiftShader)']));
        $this->assertSame(['software-rendering:webgl_renderer'],
            Fingerprint::headlessReasons(['webgl_renderer' => 'llvmpipe (LLVM 15)']));
        $this->assertSame(['software-rendering:webgl_vendor', 'software-rendering:webgl_renderer'],
            Fingerprint::headlessReasons(['webgl_vendor' => 'SwiftShader', 'webgl_renderer' => 'LLVMpipe']));
        // real GPUs, silence, and junk stay clean
        $this->assertSame([], Fingerprint::headlessReasons(['webgl_vendor' => 'Google Inc. (NVIDIA)', 'webgl_renderer' => 'ANGLE (NVIDIA GeForce RTX 4060)']));
        $this->assertSame([], Fingerprint::headlessReasons([]));
        $this->assertSame([], Fingerprint::headlessReasons(['webgl_vendor' => 'Mesa off-screen']));
    }

    public function testAutomationBandsSplitCleanFlaggedUnknown(): void
    {
        $bands = Fingerprint::automationBands([
            ['platform' => 'Win32', 'ua_platform' => 'Windows', 'ua_mobile' => '0'],
            ['platform' => 'MacIntel', 'ua_platform' => 'Windows'],              // conflict
            ['webgl_vendor' => 'SwiftShader'],                                   // software rendering
            ['platform' => 'Win32', 'ua_mobile' => '1'],                         // conflict
            [],
            'malformed-row',
        ]);
        $this->assertSame(1, $bands['clean']);
        $this->assertSame(3, $bands['flagged']);
        $this->assertSame(2, $bands['unknown'], 'empty and malformed rows are unknown, not flagged.');
        $this->assertSame(6, array_sum($bands), 'one profile in, exactly one verdict out.');
        // flagged is interpretation only; an empty crowd never flags anything
        $this->assertSame(['clean' => 0, 'flagged' => 0, 'unknown' => 0], Fingerprint::automationBands([]));
    }

    public function testCompletenessCountsTheReportedSignals(): void
    {
        $full = ['platform' => 'Win32', 'ua_platform' => 'Windows', 'ua_mobile' => '0',
            'webgl_vendor' => 'Google Inc. (NVIDIA)', 'webgl_renderer' => 'ANGLE (NVIDIA)'];
        $this->assertSame(5, Fingerprint::completeness($full), 'all known signals reported.');
        $this->assertSame(1, Fingerprint::completeness(['platform' => 'Win32', 'ua_platform' => '']), 'an empty value is not a reported signal.');
        $this->assertSame(0, Fingerprint::completeness([]));
        $this->assertSame(0, Fingerprint::completeness(['platform' => '   ']), 'whitespace-only values do not count as reported.');
        // the SIGNALS law stays narrow: only keys this class interprets
        $this->assertTrue(count(Fingerprint::SIGNALS) < 21, 'interpretation stays narrower than the 20 collected signals.');
    }

    public function testImpossiblesCatchDeviceLies(): void
    {
        // a phone family that claims zero touch points is a desktop in costume
        $this->assertSame(['touchless-ios'],
            Fingerprint::impossibles(['platform' => 'iPhone', 'ua_platform' => 'iOS', 'ua_mobile' => '1', 'touch' => '0']));
        $this->assertSame(['touchless-android'],
            Fingerprint::impossibles(['platform' => 'Linux x86_64', 'ua_platform' => 'Android', 'ua_mobile' => '1', 'touch' => '0']));
        // a desktop in a mobile family with a screen wider than any phone or tablet
        $this->assertSame(['desktop-screen-ios'],
            Fingerprint::impossibles(['platform' => 'iPhone', 'ua_mobile' => '1', 'touch' => '5', 'screen' => '2048x1536']), 'iPads top out around 1366.');
        // core counts: junk, zero, and 999 are lies; 128-thread server CPUs are real
        $this->assertSame([], Fingerprint::impossibles(['platform' => 'Win32', 'cores' => '128']), 'a wide desktop CPU is real.');
        $this->assertSame([], Fingerprint::impossibles(['platform' => 'Win32', 'cores' => '8']));
        $this->assertTrue(in_array('cores-implausible', Fingerprint::impossibles(['platform' => 'Win32', 'cores' => '999']), true));
        $this->assertTrue(in_array('cores-implausible', Fingerprint::impossibles(['platform' => 'Win32', 'cores' => 'abc']), true));
        $this->assertTrue(in_array('cores-implausible', Fingerprint::impossibles(['platform' => 'Win32', 'cores' => '0']), true));
        // memory tiers: Chromium reports exactly 0.25/0.5/1/2/4/8, silence in other browsers
        $this->assertSame([], Fingerprint::impossibles(['platform' => 'Win32', 'mem' => '8']));
        $this->assertSame([], Fingerprint::impossibles([]), 'an empty mem field is silence, not a lie.');
        $this->assertTrue(in_array('memory-off-scale', Fingerprint::impossibles(['platform' => 'Win32', 'mem' => '7']), true));
        $this->assertTrue(in_array('memory-off-scale', Fingerprint::impossibles(['platform' => 'Win32', 'mem' => '16']), true));
        // honest desktops never trip the mobile-only hints
        $this->assertSame([], Fingerprint::impossibles(['platform' => 'Win32', 'touch' => '0', 'screen' => '1920x1080']));
    }

    public function testTimezoneOffsetsAreCheckedAgainstTheNamedZone(): void
    {
        // honest: New York in November is UTC-5, JS reports +300 minutes west
        $this->assertSame([], Fingerprint::impossibles(['tz' => 'America/New_York', 'tz_offset' => '300']));
        // honest: Sydney in November is UTC+11, JS reports -660 minutes west
        $this->assertSame([], Fingerprint::impossibles(['tz' => 'Australia/Sydney', 'tz_offset' => '-660']));
        // a lie: no probe time (now, +90d, -90d) makes New York land on +330
        $this->assertSame(['timezone-offset-mismatch'],
            Fingerprint::impossibles(['tz' => 'America/New_York', 'tz_offset' => '330']), 'the claim matches no DST phase.');
        // an offset that parses but a zone that cannot be probed is skipped silently
        $this->assertSame([], Fingerprint::impossibles(['tz' => 'Etc/Unknown', 'tz_offset' => '300']));
        // a junk offset is unparseable, not a mismatch
        $this->assertSame(['timezone-offset-unparseable'], Fingerprint::impossibles(['tz' => 'America/New_York', 'tz_offset' => 'abc']));
        $this->assertSame([], Fingerprint::impossibles(['tz' => 'America/New_York']), 'no offset reported means nothing to check.');
    }

    public function testAutomationBandsAbsorbImpossibleHints(): void
    {
        // a profile whose only automation signal is an impossible device hint
        // is flagged, with no conflict and no software renderer present
        $bands = Fingerprint::automationBands([
            ['platform' => 'Win32', 'mem' => '7'],          // off-scale memory tier only
            ['platform' => 'Win32', 'ua_platform' => 'Windows', 'ua_mobile' => '0'],
        ]);
        $this->assertSame(1, $bands['flagged']);
        $this->assertSame(1, $bands['clean']);
        // the existing 1/3/2 battery law is untouched: none of its rows carry device hints
        $stable = Fingerprint::automationBands([
            ['platform' => 'Win32', 'ua_platform' => 'Windows', 'ua_mobile' => '0'],
            ['platform' => 'MacIntel', 'ua_platform' => 'Windows'],
            ['webgl_vendor' => 'SwiftShader'],
            ['platform' => 'Win32', 'ua_mobile' => '1'],
            [],
            'malformed-row',
        ]);
        $this->assertSame(['clean' => 1, 'flagged' => 3, 'unknown' => 2], $stable);
    }

    public function testHitsMapReasonSeveritiesOntoWafInput(): void
    {
        $hits = Fingerprint::hits(['platform' => 'iPhone', 'ua_platform' => 'iOS', 'ua_mobile' => '1', 'touch' => '0']);
        $this->assertCount(1, $hits, 'one impossible hint, one hit.');
        $this->assertSame('fp-touchless-ios', $hits[0]['rule'], 'the rule names the reason verbatim so the incident shows its cause.');
        $this->assertSame(
            \SiteGuard\Core\Waf\Rules::GROUP_PROFILE, $hits[0]['group'],
            'profile lies form their own group in the corpus vocabulary.'
        );
        $this->assertSame(4, $hits[0]['severity'], 'a touch-free phone contradicts the family itself: severity 4.');
        $this->assertSame('touchless-ios', $hits[0]['evidence'], 'evidence stays the machine-named reason.');

        // the mid bar: a Chromium-only tier contradicted, and a timezone lie
        $this->assertSame(3, Fingerprint::hits(['platform' => 'Win32', 'mem' => '7'])[0]['severity']);
        $this->assertSame(3, Fingerprint::hits(['platform' => 'Win32', 'cores' => '999'])[0]['severity']);
        $this->assertSame(3, Fingerprint::hits(['tz' => 'America/New_York', 'tz_offset' => '330'])[0]['severity']);
        // junk sits at the bottom, not beside demonstrated lies
        $this->assertSame(1, Fingerprint::hits(['tz' => 'America/New_York', 'tz_offset' => 'abc'])[0]['severity']);
    }

    public function testHitsAreEmptyForCleanAndEmptyProfiles(): void
    {
        $this->assertSame([], Fingerprint::hits([]), 'an empty profile scores nothing.');
        $this->assertSame([], Fingerprint::hits(['platform' => 'Win32', 'ua_platform' => 'Windows', 'ua_mobile' => '0', 'touch' => '0', 'screen' => '1920x1080']),
            'an honest desktop is clean even with zero touch points.');
        $this->assertSame([], Fingerprint::hits(['tz' => 'America/New_York', 'tz_offset' => '300']));
    }

    public function testMultipleDeviceLiesProduceMultipleHits(): void
    {
        $hits = Fingerprint::hits([
            'platform' => 'iPhone', 'ua_platform' => 'iOS', 'ua_mobile' => '1',
            'touch' => '0', 'screen' => '2048x1536', 'mem' => '7', 'tz' => 'America/New_York', 'tz_offset' => '330',
        ]);
        $rules = array_map(static fn (array $hit): string => $hit['rule'], $hits);
        $this->assertSame(['fp-touchless-ios', 'fp-desktop-screen-ios', 'fp-memory-off-scale', 'fp-timezone-offset-mismatch'], $rules,
            'every impossibility becomes its own scoring hit, in impossibles() order.');
    }

    public function testHitsNeverThrowOnJunkProfiles(): void
    {
        $hits = Fingerprint::hits(['platform' => 123, 'screen' => true, 'tz' => [], 'tz_offset' => 'x' . "\x80"]);
        $this->assertTrue(count($hits) <= 1, 'junk values read as silence or one low hit, never a crash.');
        foreach ($hits as $hit) {
            $this->assertTrue($hit['severity'] <= 1, 'junk that does score stays at the bottom bar.');
            $this->assertSame(\SiteGuard\Core\Waf\Rules::GROUP_PROFILE, $hit['group']);
        }
    }

    public function testVerdictBandsMatchAutomationBands(): void
    {
        $profiles = [
            ['platform' => 'Win32', 'ua_platform' => 'Windows', 'ua_mobile' => '0'],
            ['platform' => 'MacIntel', 'ua_platform' => 'Windows'],
            ['webgl_vendor' => 'SwiftShader'],
            ['platform' => 'Win32', 'mem' => '7'],
            ['platform' => 'Win32', 'touch' => '0'],
            [],
        ];
        $bands = Fingerprint::automationBands($profiles);
        $per = ['clean' => 0, 'flagged' => 0, 'unknown' => 0];
        foreach ($profiles as $profile) {
            $per[Fingerprint::verdict($profile)]++;
        }
        $this->assertSame($bands, $per, 'verdict() is the one-profile law automationBands() counts.');
    }

    public function testProfileGroupCountsAsAProbeHit(): void
    {
        $hit = Fingerprint::hits(['platform' => 'iPhone', 'ua_mobile' => '1', 'touch' => '0']);
        $this->assertTrue(\SiteGuard\Core\Waf\Inspector::hasProbeHit($hit),
            'a device lie IS an application signal: it satisfies the probe-partner law on its own.');
    }
}
