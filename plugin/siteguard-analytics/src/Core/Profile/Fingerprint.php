<?php
declare(strict_types=1);

namespace SiteGuard\Core\Profile;

/**
 * Pure interpretation of the browser fingerprint signals the Beacon already
 * collected and the visitor rows already store: the platform family a client
 * claims, whether its own hints agree with each other (the tell-tale sign of
 * a spoofed client), and whether it renders in software (the headless-bot
 * default). Everything here runs on stored profile arrays and reads existing
 * stores — it adds no collection.
 */
final class Fingerprint
{
    /** @var list<string> the platform families a profile can resolve to */
    public const PLATFORMS = ['windows', 'mac', 'ios', 'android', 'linux', 'chromeos', 'other', 'unknown'];

    /** @var list<string> the Beacon signal keys this class understands */
    public const SIGNALS = ['platform', 'ua_platform', 'ua_mobile', 'webgl_vendor', 'webgl_renderer'];

    /** @var list<string> the device-capability signals impossibles() reads */
    public const DEVICE_HINTS = ['screen', 'touch', 'cores', 'mem', 'tz', 'tz_offset'];

    /**
     * How strongly each impossible-device-hint reason scores inside the WAF.
     * The ranking follows the false-positive posture of each family: a
     * contradiction against the claimed device family itself (a touch-free
     * phone, a 2000px-wide iPhone) is the tightest evidence, so it sits at
     * the same severity as unambiguous attack probes; off-scale memory and
     * core tiers sit one bar lower because the tiers are Chromium's enum and
     * tampered clients fudge them; an unparseable timezone offset is junk,
     * not a demonstrated lie, and stays at the bottom. Reasons missing from
     * this map score nothing: a new reason must be classified here before it
     * can ever deny anything.
     * @var array<string,int>
     */
    private const HIT_SEVERITY = [
        'touchless-ios' => 4,
        'desktop-screen-ios' => 4,
        'touchless-android' => 4,
        'timezone-offset-mismatch' => 3,
        'memory-off-scale' => 3,
        'cores-implausible' => 3,
        'timezone-offset-unparseable' => 1,
    ];

    /**
     * One profile onto one platform family, first match wins. The two hints
     * are read together because real browsers phrase the same fact different
     * ways: 'Win32' + 'Windows', 'MacIntel' + 'macOS', 'Linux x86_64 Android'
     * on phones. iOS reports 'Mac' and 'iPhone' alike, so 'mac' loses to any
     * earlier iOS match plus the mobile-claim check below.
     * @param array<string,mixed> $profile
     */
    public static function platform(array $profile): string
    {
        $claimed = strtolower((string) ($profile['platform'] ?? ''));
        $ua = strtolower((string) ($profile['ua_platform'] ?? ''));
        $joined = $claimed . ' ' . $ua;
        $mobile = in_array((string) ($profile['ua_mobile'] ?? ''), ['1', 'true'], true);

        foreach (['win' => 'windows', 'iphone' => 'ios', 'ipod' => 'ios', 'ipad' => 'ios',
            'android' => 'android', 'ios' => 'ios', 'cros' => 'chromeos', 'chrome os' => 'chromeos'] as $needle => $family) {
            if (str_contains($joined, $needle)) {
                return $family;
            }
        }
        if (str_contains($joined, 'mac')) {
            return $mobile ? 'ios' : 'mac';
        }
        if (str_contains($joined, 'linux')) {
            return 'linux';
        }
        return $joined === ' ' ? 'unknown' : 'other';
    }

    /**
     * Rolls a crowd of profiles into platform family counts. Every profile
     * lands in exactly one band, including the 'unknown' band for rows that
     * reported nothing usable.
     * @param list<array<string,mixed>> $profiles
     * @return array<string,int> family => visitor count, every family present
     */
    public static function platformBands(array $profiles): array
    {
        $bands = array_fill_keys(self::PLATFORMS, 0);
        foreach ($profiles as $profile) {
            $bands[is_array($profile) ? self::platform($profile) : 'unknown']++;
        }
        return $bands;
    }

    /**
     * Places where a client's own hints disagree with each other — the honest
     * browser gets these right, and tampering often gets exactly one wrong.
     * Compatibility keeps the two real-world overlaps honest: iPadOS reports
     * 'Mac', and Android's Chrome reports 'Linux' as navigator.platform, so
     * neither pair counts as a conflict.
     * @param array<string,mixed> $profile
     * @return list<string> machine-named disagreement reasons
     */
    public static function conflicts(array $profile): array
    {
        $claimed = self::platform(['platform' => $profile['platform'] ?? '']);
        $stated = self::platform(['ua_platform' => $profile['ua_platform'] ?? '']);
        $mobile = (string) ($profile['ua_mobile'] ?? '');

        $reasons = [];
        $compatible = [
            'mac' => ['mac', 'ios'],
            'ios' => ['ios', 'mac'],
            'android' => ['android', 'linux'],
            'linux' => ['linux', 'android'],
            'chromeos' => ['chromeos', 'linux'],
            'windows' => ['windows'],
        ];
        // both sides must name a real family; 'unknown' proves the field is
        // absent, not that the client lied
        if (isset($compatible[$claimed], $compatible[$stated])
            && $stated !== $claimed && !in_array($stated, $compatible[$claimed], true)) {
            $reasons[] = 'claimed:' . $claimed . '-stated:' . $stated;
        }
        if ($mobile === '1' && $claimed === 'windows') {
            $reasons[] = 'claimed:windows-stated:mobile';
        }
        if ($mobile === '0' && in_array($claimed, ['ios'], true)) {
            $reasons[] = 'claimed:ios-stated:desktop';
        }
        return $reasons;
    }

    /**
     * The WebGL headless fingerprint: SwiftShader and llvmpipe are software
     * renderers, never the GPU a real desktop or phone ships with. Ordinary
     * browsers never name them, so the reason list is short by design.
     * @param array<string,mixed> $profile
     * @return list<string>
     */
    public static function headlessReasons(array $profile): array
    {
        $reasons = [];
        foreach (['webgl_vendor', 'webgl_renderer'] as $key) {
            $value = strtolower((string) ($profile[$key] ?? ''));
            if ($value === '') {
                continue;
            }
            if (str_contains($value, 'swiftshader') || str_contains($value, 'llvmpipe')) {
                $reasons[] = 'software-rendering:' . $key;
            }
        }
        return $reasons;
    }

    /**
     * Device hints that cannot all be true: a client claiming a mobile family
     * while reporting hardware no real device of that family ships with. The
     * thresholds read the Beacon's own value formats — screen is "WxH" CSS
     * pixels of the hardware screen, touch/cores are decimal strings, mem is
     * the Chromium-only memory tier (a browser other than Chromium leaves it
     * EMPTY, which is silence, not a lie), tz an IANA zone name, tz_offset the
     * JS minutes (positive west of UTC). Everything here is evidence only:
     * enforcement lives in the WAF, never in this class.
     * @param array<string,mixed> $profile
     * @return list<string> machine-named impossible-hint reasons
     */
    public static function impossibles(array $profile): array
    {
        $reasons = [];
        $family = self::platform($profile);
        $isMobileFamily = $family === 'ios' || $family === 'android';
        $touch = (string) ($profile['touch'] ?? '');

        // every real iOS or Android device reports touch points (iPhones
        // report 5); touch === '0' is a desktop browser talking over a
        // mobile platform's identity
        if ($isMobileFamily && $touch === '0') {
            $reasons[] = 'touchless-' . $family;
        }
        // phones and tablets peak far below 2000 CSS pixels in one dimension
        // (iPads top out around 1366), so a screen at least that wide is a
        // desktop pretending to be one
        $screen = (string) ($profile['screen'] ?? '');
        if (preg_match('/^(\d+)x(\d+)$/', $screen, $m) === 1 && $family === 'ios'
            && max((int) $m[1], (int) $m[2]) >= 2000) {
            $reasons[] = 'desktop-screen-ios';
        }
        $cores = (string) ($profile['cores'] ?? '');
        if ($cores !== '' && (!is_numeric($cores) || (int) round((float) $cores) < 1 || (float) $cores > 256)) {
            // wide-server CPUs genuinely reach 128 threads, so the band is
            // generous: junk ('x', negative, zero) or a 999 core report
            $reasons[] = 'cores-implausible';
        }
        $mem = (string) ($profile['mem'] ?? '');
        if ($mem !== '' && !in_array($mem, ['0.25', '0.5', '1', '2', '4', '8'], true)) {
            // Chromium reports exactly these tiers; anything else named here is
            // off the scale of the deviceMemory API
            $reasons[] = 'memory-off-scale';
        }
        $zone = (string) ($profile['tz'] ?? '');
        $offset = (string) ($profile['tz_offset'] ?? '');
        if ($offset !== '' && !is_numeric($offset)) {
            $reasons[] = 'timezone-offset-unparseable';
        } elseif ($offset !== '' && $zone !== '') {
            try {
                $probe = new \DateTimeZone($zone);
            } catch (\Exception) {
                // unresolvable zone names (real-world 'Etc/Unknown') prove
                // absence of information, not lying — skipped silently
                $probe = null;
            }
            // the JS offset is minutes west, PHP seconds east, matched over
            // now and both half-year probes so DST either hemisphere holds
            if ($probe instanceof \DateTimeZone && self::zonesAgree($probe, -(float) $offset * 60) === false) {
                $reasons[] = 'timezone-offset-mismatch';
            }
        }
        return $reasons;
    }

    /**
     * The impossible-device-hint reasons as WAF-scoring input: same shape the
     * Inspector returns for pattern hits, so a profile lie and a payload
     * signature score through one path in Gate. The rule id carries the
     * reason verbatim ("fp-touchless-ios") so every incident names its cause.
     * Severities come from HIT_SEVERITY; reasons missing from that map are
     * skipped, not guessed. A clean or empty profile scores nothing.
     * @param array<string,mixed> $profile
     * @return list<array{rule:string,group:string,severity:int,evidence:string}>
     */
    public static function hits(array $profile): array
    {
        $hits = [];
        foreach (self::impossibles($profile) as $reason) {
            $severity = self::HIT_SEVERITY[$reason] ?? 0;
            if ($severity === 0) {
                continue;
            }
            $hits[] = [
                'rule' => 'fp-' . $reason,
                'group' => \SiteGuard\Core\Waf\Rules::GROUP_PROFILE,
                'severity' => $severity,
                'evidence' => $reason,
            ];
        }
        return $hits;
    }

    /**
     * One verdict for one profile: 'flagged' carries at least one automation
     * signal (self-disagreement, a software renderer, or a device hint no
     * real device of that family ships with), 'clean' reported signals with
     * none of those, 'unknown' an empty or malformed row that proves nothing
     * either way. automationBands() counts these; keep the two laws together.
     * @param array<string,mixed> $profile
     * @return string clean|flagged|unknown
     */
    public static function verdict(array $profile): string
    {
        if ($profile === []) {
            return 'unknown';
        }
        $flagged = self::conflicts($profile) !== [] || self::headlessReasons($profile) !== []
            || self::impossibles($profile) !== [];
        return $flagged ? 'flagged' : 'clean';
    }

    /**
     * True when the PHP-side offset for a zone equals the claimed seconds
     * east at the current time or at either half-year probe. A zone that
     * cannot be probed resolves to null and its profile is skipped silently
     * (real-world 'Etc/Unknown' values prove absence, not lying).
     */
    private static function zonesAgree(\DateTimeZone $zone, float $secondsEast): ?bool
    {
        $agrees = null;
        foreach (['now', '+90 days', '-90 days'] as $probe) {
            try {
                $target = new \DateTimeImmutable($probe, $zone);
            } catch (\Exception) {
                return null;
            }
            $actual = $zone->getOffset($target);
            if ((float) $actual === $secondsEast) {
                return true;
            }
            $agrees = false;
        }
        return $agrees;
    }

    /**
     * Verdict bands for a crowd: 'flagged' means the stored profile carries at
     * least one automation signal (a hint conflict, a software renderer, or a
     * device hint no real device of that family ships with), not that the
     * request was blocked — enforcement lives in the WAF, never here.
     * An empty or malformed row proves nothing either way, so it stays unknown.
     * @param list<array<string,mixed>> $profiles
     * @return array<string,int> clean / flagged / unknown counts
     */
    public static function automationBands(array $profiles): array
    {
        $bands = ['clean' => 0, 'flagged' => 0, 'unknown' => 0];
        foreach ($profiles as $profile) {
            $bands[is_array($profile) ? self::verdict($profile) : 'unknown']++;
        }
        return $bands;
    }

    /**
     * How many of the known signals this profile actually reported (0..N).
     * The completeness count is itself a fingerprint: an empty or one-field
     * profile is what a script that skips the Beacon work leaves behind.
     * @param array<string,mixed> $profile
     */
    public static function completeness(array $profile): int
    {
        $count = 0;
        foreach (self::SIGNALS as $key) {
            if (isset($profile[$key]) && (string) $profile[$key] !== '' && trim((string) $profile[$key]) !== '') {
                $count++;
            }
        }
        return $count;
    }
}
