<?php
declare(strict_types=1);

namespace SiteGuard\Wp\Admin;

use SiteGuard\Core\Profile\Fingerprint;
use SiteGuard\Core\Profile\Segments;
use SiteGuard\Wp\Analytics;
use SiteGuard\Wp\Caps;
use SiteGuard\Wp\Installer;

/**
 * The Profiles section: who the visitors are and what they look at, built
 * entirely from data the plugin already collected on the other sections.
 * Nothing is newly collected here: identity stays pseudonymous (visitor ids
 * and their page paths), capability bands read the browser hints already on
 * the visitor rows, and no geography or personal detail is added beyond what
 * the existing consent and ip_storage settings permit.
 */
final class Profiles
{
    public static function section(): void
    {
        if (!Caps::userCan(Caps::VIEW_ANALYTICS)) {
            return;
        }

        $analytics = new Analytics($GLOBALS['wpdb']);
        $since = time() - 30 * 86400;
        $totals = $analytics->totals($since);
        $visitors = $analytics->recentVisitors($since, 100);
        $devices = $analytics->devices($since);
        $profiles = self::collectProfiles($since);

        Views::openSection('profiles');
        Views::sectionTitle('Profiles', 'What your visitors look like and want — drawn from data this site already collects, and nothing more.');

        Views::openCard('Who is visiting', 'last 30 days');
        $returning = (int) ($GLOBALS['wpdb']->get_var($GLOBALS['wpdb']->prepare(
            'SELECT COUNT(*) FROM ' . Installer::tables()['visitors'] . ' WHERE sessions > 1 AND last_seen >= %s',
            gmdate('Y-m-d H:i:s', $since)
        )) ?? 0);
        $mobileViews = 0;
        $totalViews = 0;
        foreach ($devices as $device) {
            $totalViews += (int) $device['views'];
            if ($device['device'] === 'mobile') {
                $mobileViews = (int) $device['views'];
            }
        }
        $mobileShare = $totalViews > 0 ? round($mobileViews / $totalViews * 100, 1) : 0.0;
        Views::stats([
            'Visitors' => number_format_i18n((int) $totals['visitors']),
            'Returning' => number_format_i18n($returning),
            'Sessions' => number_format_i18n((int) $totals['sessions']),
            'Mobile share' => $mobileShare . '%',
            'Pageviews' => number_format_i18n((int) $totals['reported_pageviews']),
        ]);
        Views::closeCard();

        self::devicesCard($devices, $profiles);
        self::fingerprintsCard($profiles);
        self::interestsCard($analytics, $since);
        self::paceCard($visitors);

        Views::openCard('What this screen does and does not know');
        echo '<p class="sg-lead">Every profile above is a pseudonymous visitor id this site assigned '
            . 'itself — not a name, not an address on file, not a login. Interest topics are the pages '
            . 'a visitor already chose to open. Capability bands come from the browser hints already '
            . 'shown on each Visitor detail. Where consent settings limit collection, these cards '
            . 'simply quiet down; nothing is inferred beyond the recorded pages.</p>';
        Views::closeCard();

        Views::closeSection();
    }

    /**
     * Device mix plus the capability bands decoded from stored browser
     * fingerprints, so a shop can see that its audience is, say, mid-memory
     * phones and order accordingly.
     * @param list<array{device:string,views:int}> $devices
     * @param list<array<string,mixed>> $profiles
     */
    private static function devicesCard(array $devices, array $profiles): void
    {
        Views::openCard('Devices and capabilities', 'browser hints already collected');
        $segments = [];
        foreach ($devices as $device) {
            if ($device['device'] === '' || $device['device'] === 'unknown') {
                $device['device'] = 'unknown';
            }
            $segments[] = ['label' => ucfirst((string) $device['device']), 'value' => (int) $device['views'],
                'tone' => $device['device'] === 'mobile' ? 'accent' : ($device['device'] === 'desktop' ? 'ok' : 'muted')];
        }
        Views::splitBar($segments);

        $memory = Segments::memoryBands($profiles);
        $cores = Segments::coresBands($profiles);
        if (array_sum($memory) > 0) {
            Views::table(
                ['Capability', 'Low', 'Mid', 'High', 'Unreported'],
                [
                    ['Device memory', esc_html(number_format_i18n($memory['small']) . ' small'), esc_html(number_format_i18n($memory['mid'])),
                        esc_html(number_format_i18n($memory['large'])), esc_html(number_format_i18n($memory['unknown']))],
                    ['CPU cores', esc_html(number_format_i18n($cores['low'])), esc_html(number_format_i18n($cores['mid'])),
                        esc_html(number_format_i18n($cores['high'])), esc_html(number_format_i18n($cores['unknown']))],
                ],
                'No visitors have reported capability hints yet.'
            );
            echo '<p class="sg-lead">Memory bands are small 1&nbsp;GB or less, mid 2-4&nbsp;GB, large 8&nbsp;GB or more; '
                . 'cores are low 4 or fewer, mid 5-8, high 9+</p>';
        }
        Views::closeCard();
    }

    /**
     * Client fingerprints: the platform mix and automation verdicts derived
     * from the browser signals already stored on the visitor rows. Display
     * only — nothing is newly collected and nothing here blocks a request.
     * @param list<array<string,mixed>> $profiles
     */
    private static function fingerprintsCard(array $profiles): void
    {
        Views::openCard('Client fingerprints', 'platform and automation hints already collected');
        $platforms = Fingerprint::platformBands($profiles);
        $tones = ['windows' => 'accent', 'mac' => 'info', 'ios' => 'accent', 'android' => 'ok', 'linux' => 'muted', 'chromeos' => 'muted', 'other' => 'muted'];
        $segments = [];
        foreach ($platforms as $family => $count) {
            if ($count === 0) {
                continue;
            }
            $segments[] = ['label' => ucfirst((string) $family), 'value' => $count, 'tone' => $tones[(string) $family] ?? 'muted'];
        }
        Views::splitBar($segments);

        $automation = Fingerprint::automationBands($profiles);
        if (array_sum($automation) > 0) {
            $conflicts = 0;
            $software = 0;
            $implausible = 0;
            foreach ($profiles as $profile) {
                $conflicts += Fingerprint::conflicts(is_array($profile) ? $profile : []) !== [] ? 1 : 0;
                $software += Fingerprint::headlessReasons(is_array($profile) ? $profile : []) !== [] ? 1 : 0;
                $implausible += Fingerprint::impossibles(is_array($profile) ? $profile : []) !== [] ? 1 : 0;
            }
            Views::table(
                ['Verdict', 'Visitors'],
                [
                    ['Clean browser hints', esc_html(number_format_i18n($automation['clean']))],
                    ['Conflicting client hints', esc_html(number_format_i18n($conflicts))],
                    ['Software-rendered WebGL (headless markers)', esc_html(number_format_i18n($software))],
                    ['Implausible device hints', esc_html(number_format_i18n($implausible))],
                    ['No usable profile', esc_html(number_format_i18n($automation['unknown']))],
                ],
                'No visitors have reported fingerprint signals yet.'
            );
            echo '<p class="sg-lead">Conflicting hints means the browser disagreed with itself, e.g. claiming '
                . 'a Mac while stating Windows, which a tampered client often gets wrong. Software-rendered '
                . 'WebGL means the graphics stack named SwiftShader or llvmpipe, the default renderers inside '
                . 'headless browser automation. Implausible device hints means the hardware a client described '
                . 'cannot exist in that family, e.g. a touch-free phone or a 5&nbsp;GB browser memory tier. All are '
                . 'evidence, not blocks: a flagged visitor is still served exactly like everyone else.</p>';
        }
        Views::closeCard();
    }

    /**
     * Interest topics: which kinds of pages the crowd actually opened.
     * @param list<array{path:string,views:int}> $paths
     */
    private static function interestsCard(Analytics $analytics, int $since): void
    {
        Views::openCard('Interests', 'topics bucketed from the pages already visited');
        $counts = Segments::topicCounts(array_map(
            static fn (array $row): int => (int) $row['views'],
            $analytics->topPaths($since, 50)
        ));
        $tones = ['shop' => 'ok', 'pricing' => 'accent', 'docs' => 'info', 'article' => 'accent', 'contact' => 'muted', 'other' => 'muted'];
        $items = [];
        foreach (array_filter($counts, static fn (int $count): bool => $count > 0) as $topic => $count) {
            $items[] = ['label' => ucfirst((string) $topic) . ' pages', 'title' => $topic, 'value' => $count];
        }
        if ($items) {
            Views::barList($items);
            echo '<p class="sg-lead">Derived from the top 50 requested paths; every path that names no topic '
                . 'lands under Other. This is what the crowd wants, in the order it asked.</p>';
        } else {
            Views::barList($items);
        }
        Views::closeCard();
    }

    /**
     * Recency and rhythm for the most recent visitors, one pace label each.
     * @param list<array<string,mixed>> $visitors
     */
    private static function paceCard(array $visitors): void
    {
        Views::openCard('Recency and pace', 'the 100 most recent visitors');
        $rows = [];
        foreach ($visitors as $visitor) {
            $first = (string) $visitor['first_seen'];
            $pace = $first === '' ? 'new' : Segments::pace(
                (int) $visitor['sessions'],
                (int) strtotime($first . ' UTC'),
                time()
            );
            $rows[] = [
                '<a href="' . esc_url(Visitors::detailUrl((string) $visitor['visitor'])) . '">'
                    . esc_html(substr((string) $visitor['visitor'], 0, 10)) . '…</a>',
                esc_html(Visitors::when((string) $visitor['last_seen'])),
                esc_html(number_format_i18n((int) $visitor['sessions'])),
                esc_html(number_format_i18n((int) $visitor['pageviews'])),
                esc_html($pace),
                esc_html((string) $visitor['device']),
            ];
        }
        Views::table(
            ['Visitor', 'Last seen', 'Sessions', 'Pageviews', 'Pace', 'Device'],
            $rows,
            'No visitors have been seen in this window yet.'
        );
        Views::closeCard();
    }

    /**
     * Decoded visitor-level fingerprints. Only rows whose stored JSON parses
     * make it into the list; a malformed row is skipped, never fatal.
     * @return list<array<string,mixed>>
     */
    private static function collectProfiles(int $since): array
    {
        $rows = (array) $GLOBALS['wpdb']->get_results($GLOBALS['wpdb']->prepare(
            'SELECT profile FROM ' . Installer::tables()['visitors'] . ' WHERE last_seen >= %s LIMIT 2000',
            gmdate('Y-m-d H:i:s', $since)
        ), ARRAY_A);
        $profiles = [];
        foreach ($rows as $row) {
            $decoded = json_decode((string) ($row['profile'] ?? ''), true);
            if (is_array($decoded)) {
                $profiles[] = $decoded;
            }
        }
        return $profiles;
    }
}
