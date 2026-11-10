<?php
declare(strict_types=1);

namespace SiteGuard\Wp\Admin;

use SiteGuard\Core\Ip;
use SiteGuard\Core\Profile\Fingerprint;
use SiteGuard\Core\Profile\Segments;
use SiteGuard\Core\Profile\Watchlist as WatchlistLogic;
use SiteGuard\Core\Subjects;
use SiteGuard\Wp\Analytics;
use SiteGuard\Wp\Caps;
use SiteGuard\Wp\Config;
use SiteGuard\Wp\Installer;
use SiteGuard\Wp\Store\WpdbIncidentStore;
use SiteGuard\Wp\Store\WpdbWatchlist;

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
    /**
     * The fixed part of the anchor vocabulary read aloud: one plain-English
     * phrase per rule string that is not a dynamic claimed:X-stated:Y pair
     * (those phrase themselves in reasonPhrase). Anything unlisted falls
     * back to its raw rule string — the table tracks
     * Watchlist::ANCHORABLE_RULES by use, and never invents a phrase.
     * @var array<string,string>
     */
    private const PHRASES = [
        'touchless-ios' => 'reports no touch on iOS',
        'desktop-screen-ios' => 'reports a desktop-sized screen on iOS',
        'touchless-android' => 'reports no touch on Android',
        'timezone-offset-mismatch' => 'timezone offset disagrees with its named zone',
        'timezone-offset-unparseable' => 'reports an unparseable timezone offset',
        'memory-off-scale' => 'reports a memory tier off the scale',
        'cores-implausible' => 'reports an implausible CPU core count',
        'claimed:windows-stated:mobile' => 'claims Windows while reporting a mobile client',
        'claimed:ios-stated:desktop' => 'claims iOS while reporting a desktop client',
        'software-rendering:webgl_vendor' => 'software WebGL vendor',
        'software-rendering:webgl_renderer' => 'software WebGL renderer',
    ];

    /**
     * The blank form's fixed POST values per anchorable rule: the report the
     * built-in detectors need to re-fire exactly that lie when
     * Actions::watchlistSave rebuilds the entry (the anchor gate refuses any
     * checked lie that does not fire, so these sit at the detectors'
     * thresholds, all shapes the Beacon itself stores for a lying client).
     * The seven impossible hints are self-describing reasons, so their keys
     * only need the hint values; renderer lies pin BOTH WebGL strings,
     * because vendor and renderer travel together. The dynamic
     * claimed:X-stated:Y pairs get their values from pairSignatures.
     * @var array<string,array<string,string>>
     */
    private const ANCHOR_FIXED_SIGNALS = [
        'touchless-ios' => ['platform' => 'iPhone', 'touch' => '0'],
        'desktop-screen-ios' => ['platform' => 'iPhone', 'screen' => '2000x1080'],
        'touchless-android' => ['platform' => 'Android', 'touch' => '0'],
        'timezone-offset-mismatch' => ['tz' => 'UTC', 'tz_offset' => '60'],
        'timezone-offset-unparseable' => ['tz_offset' => 'not-a-number'],
        'memory-off-scale' => ['mem' => '7'],
        'cores-implausible' => ['cores' => '999'],
        'claimed:windows-stated:mobile' => ['platform' => 'Win32', 'ua_mobile' => '1'],
        'claimed:ios-stated:desktop' => ['platform' => 'iPhone', 'ua_mobile' => '0'],
        'software-rendering:webgl_vendor' => [
            'webgl_vendor' => 'Google Inc. (SwiftShader)', 'webgl_renderer' => 'ANGLE (SwiftShader)'],
        'software-rendering:webgl_renderer' => [
            'webgl_vendor' => 'Google Inc. (SwiftShader)', 'webgl_renderer' => 'ANGLE (SwiftShader)'],
    ];

    /**
     * Plain labels for the signal keys the anchor checkboxes carry, so the
     * fixed-report hint under each checkbox reads in words.
     * @var array<string,string>
     */
    private const ANCHOR_SIGNAL_LABELS = [
        'platform' => 'platform claim',
        'ua_platform' => 'stated platform',
        'ua_mobile' => 'mobile claim',
        'webgl_vendor' => 'WebGL vendor',
        'webgl_renderer' => 'WebGL renderer',
        'touch' => 'touch points',
        'screen' => 'screen',
        'cores' => 'CPU cores',
        'mem' => 'device memory',
        'tz' => 'time zone',
        'tz_offset' => 'UTC offset',
    ];

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
        self::watchlistCard($profiles, $since);
        self::candidatesCard($since);
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
     * Owner-saved fingerprint profiles feeding the content gate. Readable
     * under VIEW_ANALYTICS; every action on it carries its own narrower
     * gate (MANAGE_BLOCKS per form, EXPORT_DATA for the export link), each
     * a nonced inline form exactly like Security's liftButton.
     * @param list<array<string,mixed>> $profiles decoded 30-day profiles, for match counts
     * @param int $since the section's 30-day window start
     */
    private static function watchlistCard(array $profiles, int $since): void
    {
        // Same store the Gate reads: the card shows the list enforcement
        // actually carries, never a parallel copy.
        $entries = (new WpdbWatchlist())->all();
        $armed = !empty(Config::settings()['waf_watchlist']);

        Views::openCard('Watchlist', 'owner-saved fingerprint profiles feeding the content gate');

        // The export link rides under the card head, gated to the export
        // capability like every other download (Operations' export row is
        // the button-styled precedent).
        if (Caps::userCan(Caps::EXPORT_DATA)) {
            $exportUrl = wp_nonce_url(
                add_query_arg('action', 'siteguard_watchlist_export', admin_url('admin-post.php')),
                'siteguard_watchlist_export'
            );
            echo '<p class="sg-wl-export"><a class="sg-foot" href="' . esc_url($exportUrl)
                . '">Download the watchlist as JSON</a></p>';
        }

        if (!$entries) {
            echo '<p class="sg-empty">The watchlist is empty. It stores the browser fingerprints you name '
                . 'yourself, so a client that keeps its tampered profile across address changes keeps matching '
                . 'the entry. Save one from the candidates card below, from any flagged visitor&rsquo;s detail '
                . 'page, or with the blank form here.</p>';
        } else {
            $counts = self::matchCounts($entries, $profiles);
            $rows = [];
            foreach ($entries as $entry) {
                $id = (string) $entry['id'];
                $rows[] = [
                    '<strong>' . esc_html((string) $entry['name']) . '</strong>'
                        . ((string) ($entry['notes'] ?? '') !== ''
                            ? '<br><span class="sg-muted">' . esc_html((string) $entry['notes']) . '</span>'
                            : ''),
                    esc_html(self::rulesPhrase((array) $entry['rules'])),
                    esc_html(number_format_i18n($counts[$id] ?? 0)),
                    esc_html(self::createdDate((int) ($entry['created'] ?? 0))),
                    self::deleteButton($id),
                ];
            }
            Views::table(
                ['Name', 'Anchored rules', 'Matches 30d', 'Created', ''],
                $rows
            );
            echo '<p class="sg-foot">Matches 30d replays the matcher over every visitor in this window and '
                . 'counts matches, not blocks — a match below the gate bar or in observe mode is counted the '
                . 'same way, so this column shows the list working whether or not anything was denied. Enforcement '
                . ($armed
                    ? 'is armed (Settings, watchlist toggle); verify a match in Observe mode first.'
                    : 'is switched off in Settings: no match scores until the watchlist toggle is on.').'</p>';
        }

        if (Caps::userCan(Caps::MANAGE_BLOCKS)) {
            self::blankForm($entries);
            self::importForm();
        }
        Views::closeCard();
    }

    /**
     * Visitor candidates: flagged fingerprints with recent gate history. One
     * card, one attribution mode by the ip_storage setting — the card states
     * which rule it used, because the proof differs by mode and honesty
     * about the proof is the point of the card.
     * @param int $since the section's 30-day window start
     */
    private static function candidatesCard(int $since): void
    {
        $ipMode = (string) Config::settings()['ip_storage'];
        Views::openCard('Candidates', 'flagged fingerprints with gate history in the last 7 days');

        if ($ipMode === 'none') {
            echo '<p class="sg-empty">Addresses are not stored in this install (Settings, address storage: none), '
                . 'so gate history cannot be attributed to the browsers in this window. A flagged visitor still '
                . 'shows its lie reasons on the Visitors screen, where you can save it as a profile by hand.</p>';
            Views::closeCard();
            return;
        }

        $since7 = time() - 7 * 86400;
        // Recent incident subjects straight from the incidents store, the
        // same rows Security reads; no new store method: recent() over the
        // window covers every subject the gate recorded, at tens of rows.
        $subjects = [];
        $subjectHashes = [];
        if ($ipMode === 'hashed') {
            // The keyed hash the beacon wrote for stored addresses is
            // hash_hmac(subject, site salt), the exact derivation the beacon
            // already performs — the subject on an incident row is that same
            // subject string, so both sides hash identically. Read directly,
            // never re-implemented.
            $salt = (string) get_option(Installer::SALT_OPTION, '');
        }
        foreach ((new WpdbIncidentStore($GLOBALS['wpdb']))->recent(200, 0) as $row) {
            $ts = (int) strtotime((string) $row['ts'] . ' UTC');
            if ($ts < $since7) {
                continue;
            }
            $subject = (string) $row['subject'];
            $subjects[$subject] = true;
            if ($ipMode === 'hashed') {
                $subjectHashes[substr(hash_hmac('sha256', $subject, $salt), 0, 32)] = true;
            }
        }

        $candidates = [];
        foreach (self::candidateVisitors($since) as $visitor) {
            if (self::attributedToGate($visitor, $subjects, $subjectHashes, $ipMode)) {
                $candidates[] = $visitor;
            }
        }

        if (!$candidates) {
            echo '<p class="sg-empty">No visitor in this window has both a flagged fingerprint and recent gate '
                . 'history. A name appears here only when the same browser both looks tampered and sits behind '
                . 'recent incidents; until then there is nothing to name.</p>';
            Views::closeCard();
            return;
        }

        $saveable = Caps::userCan(Caps::MANAGE_BLOCKS);
        $rows = [];
        foreach ($candidates as $candidate) {
            $profile = is_array($candidate['profile'] ?? null) ? $candidate['profile'] : [];
            $row = [
                '<a href="' . esc_url(Visitors::detailUrl((string) $candidate['visitor'])) . '"><code>'
                    . esc_html(substr((string) $candidate['visitor'], 0, 10)) . '…</code></a>',
                esc_html(Visitors::when((string) $candidate['last_seen'])),
                esc_html(self::rulesPhrase(array_values(array_merge(
                    Fingerprint::impossibles($profile),
                    Fingerprint::conflicts($profile),
                    Fingerprint::headlessReasons($profile)
                )))),
                $saveable ? self::saveButton((string) $candidate['visitor']) : '',
            ];
            $rows[] = $row;
        }
        Views::table(
            ['Visitor', 'Last seen', 'The lies it tells', ''],
            $rows
        );
        echo '<p class="sg-foot">Saved via the visitor form, the entry re-derives this browser&rsquo;s lie set '
            . 'itself: the button carries no anchors, and nothing is pre-checked that the server cannot verify. '
            . 'Saving does not block anyone &mdash; the content gate still decides.</p>';
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
                . 'cannot exist in that family, e.g. a touch-free phone or a 5&nbsp;GB browser memory tier. '
                . 'Implausible device hints are signed rules: with device-hint enforcement armed in Settings they '
                . 'score like attack signatures, and the block lands on the network address. Conflicts and '
                . 'software renderers remain evidence only. A flagged visitor is still served exactly like '
                . 'everyone else until the content gate itself crosses a threshold.</p>';
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

    /**
     * Match counts per entry id: a replay of Watchlist::hits over every
     * decoded profile in the window (the population this section reports),
     * counting each match once — observe-mode hits, below-bar hits, and
     * denied hits all count the same, because the column reports the list
     * firing, not the gate's verdict.
     * @param list<array> $entries @param list<array<string,mixed>> $profiles
     * @return array<string,int> entry id => matched visitor count
     */
    private static function matchCounts(array $entries, array $profiles): array
    {
        if ($entries === [] || $profiles === []) {
            return [];
        }
        $counts = [];
        foreach ($profiles as $profile) {
            foreach (WatchlistLogic::hits(is_array($profile) ? $profile : [], $entries) as $hit) {
                $id = (string) ($hit['evidence']['id'] ?? '');
                if ($id !== '') {
                    $counts[$id] = ($counts[$id] ?? 0) + 1;
                }
            }
        }
        return $counts;
    }

    /**
     * The human phrasing of one anchored reason, in the closed vocabulary:
     * fixed reasons read from PHRASES, the dynamic conflict pairs phrase
     * themselves, any string outside that vocabulary stays its raw rule
     * string rather than inventing a reading.
     */
    private static function reasonPhrase(string $rule): string
    {
        if (isset(self::PHRASES[$rule])) {
            return self::PHRASES[$rule];
        }
        if (str_starts_with($rule, 'claimed:') && str_contains($rule, '-stated:')) {
            $pair = explode('-stated:', substr($rule, strlen('claimed:')), 2);
            return 'claims ' . str_replace('-', ' ', $pair[0]) . ' while stating '
                . str_replace('-', ' ', $pair[1] ?? '');
        }
        return $rule;
    }

    /** @param list<string> $rules */
    private static function rulesPhrase(array $rules): string
    {
        return implode('; ', array_map([self::class, 'reasonPhrase'], $rules));
    }

    /** The created stamp, a plain UTC date: the exact day is the value. */
    private static function createdDate(int $created): string
    {
        return $created > 0 ? gmdate('Y-m-d', $created) : '—';
    }

    /** Delete as an inline nonced form, the liftButton pattern. */
    private static function deleteButton(string $id): string
    {
        if (!Caps::userCan(Caps::MANAGE_BLOCKS)) {
            return '';
        }
        return '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" class="sg-inline">'
            . '<input type="hidden" name="action" value="siteguard_watchlist_delete">'
            . '<input type="hidden" name="_wpnonce" value="' . esc_attr(wp_create_nonce('siteguard_watchlist_delete')) . '">'
            . '<input type="hidden" name="id" value="' . esc_attr($id) . '">'
            . '<button type="submit" class="button button-small">Delete</button>'
            . '</form>';
    }

    /** Save-as on one candidate row or a visitor detail: a hidden id only. */
    private static function saveButton(string $visitorId): string
    {
        if (!Caps::userCan(Caps::MANAGE_BLOCKS)) {
            return '';
        }
        // The handler's visitor path: it re-reads the stored profile and
        // re-derives every lie itself, so the form POSTs only the visitor id
        // and the save handler lands on the Profiles section, where the new
        // entry is visible with the anchored rules it verified.
        return '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" class="sg-inline">'
            . '<input type="hidden" name="action" value="siteguard_watchlist_save">'
            . '<input type="hidden" name="_wpnonce" value="' . esc_attr(wp_create_nonce('siteguard_watchlist_save')) . '">'
            . '<input type="hidden" name="visitor_id" value="' . esc_attr($visitorId) . '">'
            . '<button type="submit" class="button button-small">Save as watchlist profile</button>'
            . '</form>';
    }

    /**
     * Create-from-blank: name, notes, and the anchor vocabulary as grouped
     * checkboxes, each carrying its rule string as one value (the group
     * field name gives the handler its anchor array) and its fixed fixed
     * values documented beside it. The handler re-derives everything
     * server-side; nothing here is trusted about which entry results.
     * @param list<array> $entries current entries, shown only as count context
     */
    private static function blankForm(array $entries): void
    {
        if (count($entries) >= 200) {
            echo '<p class="sg-empty">The watchlist is at its 200-entry limit: remove one before adding another.</p>';
            return;
        }
        echo '<h4 class="sg-wl-form-head">Name a profile from blank</h4>';
        echo '<p class="sg-lead">Choose the lies to anchor; each carries the exact report the built-in detectors fire on, '
            . 'and the server re-derives the entry from those values &mdash; it refuses any checked lie that does not '
            . 're-fire, so nothing but an honest detection can be saved.</p>';
        $index = 0;
        Views::formOpen('siteguard_watchlist_save', 'siteguard_watchlist_save');
        echo '<table class="form-table" role="presentation"><tbody>';
        echo '<tr><th scope="row"><label for="sg-wl-name">Name</label></th><td>';
        echo '<input type="text" name="name" id="sg-wl-name" class="regular-text" required maxlength="191" placeholder="One attacker, named">';
        echo '</td></tr>';
        echo '<tr><th scope="row"><label for="sg-wl-notes">Notes</label></th><td>';
        echo '<textarea name="notes" id="sg-wl-notes" rows="2" class="large-text" maxlength="1000" placeholder="Why this browser matters (kept with the entry)"></textarea>';
        echo '</td></tr>';
        foreach (self::anchorGroups() as $groupLabel => $rules) {
            echo '<tr><th scope="row">' . esc_html($groupLabel) . '</th><td><fieldset class="sg-wl-anchors">';
            foreach ($rules as $rule) {
                // One explicit index per anchor: PHP's [] parsing would put
                // each checkbox and its hidden signals into SEPARATE items if
                // the index counted itself, so every anchor names its own
                // slot. An unchecked box still posts its (ignored) signals;
                // the handler reads the rule as absent and skips the whole
                // item — silence, never trust.
                $anchorIndex = (string) $index;
                $fixed = self::anchorFixedSignals($rule);
                $labels = [];
                foreach ($fixed as $key => $value) {
                    $labels[] = (self::ANCHOR_SIGNAL_LABELS[$key] ?? $key) . ' ' . $value;
                }
                echo '<label class="sg-wl-anchor">'
                    . '<input type="checkbox" name="anchors[' . esc_attr($anchorIndex) . '][rule]" value="' . esc_attr($rule) . '"> '
                    . '<span>' . esc_html(self::reasonPhrase($rule)) . '</span>';
                foreach ($fixed as $key => $value) {
                    echo '<input type="hidden" name="anchors[' . esc_attr($anchorIndex) . '][signals]['
                        . esc_attr($key) . ']" value="' . esc_attr($value) . '">';
                }
                echo '<em class="sg-wl-fixed">' . esc_html(implode('; ', $labels)) . '</em></label>';
                $index++;
            }
            echo '</fieldset></td></tr>';
        }
        echo '</tbody></table>';
        Views::formClose('Save watchlist profile');
    }

    /**
     * The anchor vocabulary grouped for the blank form: contradictions,
     * software rendering, impossible hardware. Grouping is display only —
     * every rule's POST shape is identical.
     * @return array<string,list<string>> group label => anchored rules
     */
    private static function anchorGroups(): array
    {
        $groups = ['Self-contradictions' => [], 'Software rendering' => [], 'Impossible hardware' => []];
        foreach (WatchlistLogic::ANCHORABLE_RULES() as $rule) {
            if (str_starts_with($rule, 'claimed:')) {
                $groups['Self-contradictions'][] = $rule;
            } elseif (str_starts_with($rule, 'software-rendering:')) {
                $groups['Software rendering'][] = $rule;
            } else {
                $groups['Impossible hardware'][] = $rule;
            }
        }
        return $groups;
    }

    /**
     * The fixed POST values one anchor carries: the ANCHOR_FIXED_SIGNALS
     * constants for the fixed-vocabulary lie, or the claimed/stated family
     * hints the dynamic pair is named for (each family names one hint both
     * Fingerprint::platform and the detectors resolve — see the pair table
     * in WatchlistTest). A rule with no entry here is refused by the
     * handler anyway, so no fallback is offered.
     * @return array<string,string>
     */
    private static function anchorFixedSignals(string $rule): array
    {
        $fixed = self::ANCHOR_FIXED_SIGNALS[$rule] ?? null;
        if ($fixed !== null) {
            return $fixed;
        }
        $pair = explode('-stated:', substr($rule, strlen('claimed:')), 2);
        return [
            'platform' => self::CLAIM_HINTS[$pair[0] ?? ''] ?? '',
            'ua_platform' => self::CLAIM_HINTS[$pair[1] ?? ''] ?? '',
        ];
    }

    /**
     * Import: the paste textarea and the file input, exactly the two sources
     * watchlistImport reads. A plain form, not Views::formOpen — a file
     * upload needs the multipart encoding that helper does not set, and the
     * nonce renders the same way (wp_nonce_field, the house inline form).
     */
    private static function importForm(): void
    {
        echo '<h4 class="sg-wl-form-head">Import entries</h4>';
        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" enctype="multipart/form-data">';
        wp_nonce_field('siteguard_watchlist_import');
        echo '<input type="hidden" name="action" value="siteguard_watchlist_import">';
        echo '<p><textarea name="payload" rows="3" class="large-text code" placeholder="Paste a SiteGuard watchlist export"></textarea></p>';
        echo '<p><input type="file" name="file"> <span class="description">or choose the exported JSON file (up to 256KB)</span></p>';
        submit_button('Import', 'secondary', 'submit', false);
        echo '</form>';
        echo '<p class="sg-foot">Import merges by entry id: the same fingerprint imported twice stays one entry, rows the server refuses are counted and dropped, and the list never grows past 200.</p>';
    }

    /**
     * One hint per platform family, the values Fingerprint's own tests and
     * the detectors resolve to that family alone (the same single-field
     * resolution pairSignals uses when it derives a stored entry's sides).
     * @var array<string,string>
     */
    private const CLAIM_HINTS = [
        'windows' => 'Win32', 'mac' => 'MacIntel', 'ios' => 'iPhone',
        'android' => 'Android', 'chromeos' => 'Chrome OS', 'linux' => 'Linux',
    ];

    /**
     * Candidates are visitors, not profiles: the rollup rows in the window
     * with their latest stored profile, the same shape paceCard renders.
     * Flag-worthiness is the verdict Fingerprint already computes — a lie
     * the built-in detectors classify; a clean or unknown row never
     * candidates here.
     * @return list<array<string,mixed>>
     */
    private static function candidateVisitors(int $since): array
    {
        // ip_hash rides along because the hashed mode compares against the
        // keyed hash the beacon itself wrote — the one value both sides of
        // the compare already agree on.
        $rows = (array) $GLOBALS['wpdb']->get_results($GLOBALS['wpdb']->prepare(
            'SELECT id, last_seen, ip, ua, device, browser, profile, ip_hash FROM '
            . Installer::tables()['visitors'] . ' WHERE last_seen >= %s LIMIT 2000',
            gmdate('Y-m-d H:i:s', $since)
        ), ARRAY_A);
        $out = [];
        foreach ($rows as $row) {
            $profile = [];
            $decoded = json_decode((string) ($row['profile'] ?? ''), true);
            if (is_array($decoded)) {
                $profile = $decoded;
            }
            if (Fingerprint::verdict($profile) !== 'flagged') {
                continue;
            }
            $out[] = [
                'visitor' => (string) $row['id'],
                'last_seen' => (string) $row['last_seen'],
                'ip' => (string) $row['ip'],
                'ip_hash' => (string) ($row['ip_hash'] ?? ''),
                'profile' => $profile,
            ];
        }
        return $out;
    }

    /**
     * Did this visitor carry gate history in the last 7 days, under the
     * storage mode the install chose? full compares the stored address
     * against the incident subjects directly; hashed compares the visitor's
     * beacon-written keyed hash against the same derivation over recent
     * incident subjects. An unattributable row (no address stored) is not
     * a candidate: the whole point of this card is naming a browser the
     * gate already saw.
     * @param array{ip:string,ip_hash:string} $visitor
     * @param array<string,true> $subjects subject => true, full mode
     * @param array<string,true> $subjectHashes keyed-subject hash => true, hashed mode
     */
    private static function attributedToGate(array $visitor, array $subjects, array $subjectHashes, string $ipMode): bool
    {
        if ($subjects === [] && $subjectHashes === []) {
            return false;
        }
        if ($ipMode === 'full') {
            $ip = (string) ($visitor['ip'] ?? '');
            return $ip !== '' && isset($subjects[Subjects::ip(Ip::subject($ip))]);
        }
        // hashed: the stored hash was written by the beacon from the same
        // derivation over the same salt, so equality means the gate saw
        // this address within the window.
        $hash = (string) ($visitor['ip_hash'] ?? '');
        return $hash !== '' && isset($subjectHashes[$hash]);
    }
}
