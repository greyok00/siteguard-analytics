<?php
declare(strict_types=1);

namespace SiteGuard\Wp\Admin;

use SiteGuard\Wp\Analytics;
use SiteGuard\Wp\Caps;
use SiteGuard\Wp\Installer;

/**
 * The visitor list and the detail view behind each row.
 *
 * A visitor id is a random first-party value, but the row it opens is not
 * anonymous: the address the request arrived from, the user agent header, and
 * every signal the browser reported are stored and shown here.
 */
final class Visitors
{
    private const DETAIL_ACTION = 'siteguard_visitor_detail';

    private const SIGNAL_LABELS = [
        'lang' => 'Browser language',
        'languages' => 'Accepted languages',
        'tz' => 'Time zone',
        'tz_offset' => 'UTC offset (minutes)',
        'screen' => 'Screen',
        'viewport' => 'Viewport',
        'dpr' => 'Device pixel ratio',
        'depth' => 'Colour depth',
        'touch' => 'Touch points',
        'cores' => 'CPU cores',
        'mem' => 'Device memory (GB)',
        'platform' => 'Platform',
        'ua_brands' => 'Client hints: brands',
        'ua_platform' => 'Client hints: platform',
        'ua_mobile' => 'Client hints: mobile',
        'ua_model' => 'Client hints: model',
        'ua_arch' => 'Client hints: architecture',
        'webgl_vendor' => 'WebGL vendor',
        'webgl_renderer' => 'WebGL renderer',
        'canvas' => 'Canvas hash',
        'audio' => 'Audio hash',
    ];

    public static function section(): void
    {
        if (!Caps::userCan(Caps::VIEW_ANALYTICS)) {
            return;
        }

        $analytics = new Analytics($GLOBALS['wpdb']);
        $selected = self::selectedId();

        Views::openSection('visitors');

        if ($selected !== '') {
            $detail = $analytics->visitorDetail($selected);
            if ($detail !== null) {
                self::detail($selected, $detail);
                self::closeSection();
                return;
            }
            Views::notice('That visitor id has no recorded rows. Showing the list instead.', 'warning');
        }

        self::list($analytics, $selected);

        Views::closeSection();
    }

    /** @param array<string,mixed> $detail */
    private static function detail(string $id, array $detail): void
    {
        /** @var array<string,mixed> $visitor */
        $visitor = (array) $detail['visitor'];
        /** @var list<array<string,mixed>> $events */
        $events = (array) $detail['events'];

        Views::sectionTitle('Visitor ' . substr($id, 0, 12) . '…', 'Everything recorded for this browser.');
        echo '<p class="sg-lead"><a href="' . esc_url(self::listUrl()) . '">&larr; All visitors</a></p>';

        Views::stats([
            'Pageviews' => number_format_i18n((int) $visitor['pageviews']),
            'Sessions' => number_format_i18n((int) $visitor['sessions']),
            'First seen' => self::date((string) $visitor['first_seen']),
            'Last seen' => self::when((string) $visitor['last_seen']),
            'Distinct addresses' => number_format_i18n((int) $detail['distinct_ips']),
            'Distinct profiles' => number_format_i18n((int) $detail['distinct_profiles']),
        ]);

        // ---- Network ----
        Views::openCard('Network', 'Addresses this browser connected from');
        $addresses = [];
        foreach ($events as $event) {
            $ip = (string) ($event['ip'] ?? '');
            if ($ip === '') {
                continue;
            }
            if (!isset($addresses[$ip])) {
                $addresses[$ip] = ['ip' => $ip, 'hits' => 0, 'last' => (string) $event['ts']];
            }
            $addresses[$ip]['hits']++;
        }
        if ($addresses) {
            $rows = [];
            foreach ($addresses as $entry) {
                $rows[] = [
                    '<code>' . esc_html($entry['ip']) . '</code>',
                    esc_html(number_format_i18n($entry['hits'])),
                    esc_html(self::when($entry['last'])),
                    self::lookups($entry['ip']),
                ];
            }
            Views::table(['Address', 'Requests', 'Last seen', 'Look up'], $rows);
            echo '<p class="sg-lead">Lookups open an external service in a new tab; nothing is sent from this site until you click one.</p>';
        } else {
            echo '<p class="sg-empty">No address was stored for this visitor. If the install was collecting before version 0.1.6, or address storage is switched off in Settings, only the keyed hash exists.</p>';
        }
        Views::closeCard();

        // ---- Browser ----
        Views::openCard('Browser and device');
        $ua = (string) ($visitor['ua'] ?? '');
        if ($ua === '') {
            foreach ($events as $event) {
                if (!empty($event['ua'])) {
                    $ua = (string) $event['ua'];
                    break;
                }
            }
        }
        $device = (string) ($visitor['device'] ?? '');
        $browser = (string) ($visitor['browser'] ?? '');
        Views::table(['Field', 'Value'], [
            ['User agent', $ua !== '' ? '<code class="sg-ua">' . esc_html($ua) . '</code>' : '—'],
            ['Device class', esc_html($device !== '' ? $device : '—')],
            ['Browser', esc_html($browser !== '' ? $browser : '—')],
            ['Last page', esc_html((string) ($visitor['last_path'] ?? ''))],
        ]);
        Views::closeCard();

        // ---- Fingerprint ----
        $profile = [];
        if (isset($visitor['profile']) && is_string($visitor['profile']) && $visitor['profile'] !== '') {
            $decoded = json_decode($visitor['profile'], true);
            if (is_array($decoded)) {
                $profile = $decoded;
            }
        }
        if (!$profile) {
            foreach ($events as $event) {
                if (!empty($event['profile']) && is_array($event['profile'])) {
                    $profile = $event['profile'];
                    break;
                }
            }
        }
        Views::openCard('Fingerprint', 'Latest values reported by the browser');
        if ($profile) {
            $rows = [];
            foreach ($profile as $key => $value) {
                $label = self::SIGNAL_LABELS[(string) $key] ?? (string) $key;
                $rows[] = [esc_html($label), '<code>' . esc_html((string) $value) . '</code>'];
            }
            Views::table(['Signal', 'Value'], $rows);
            echo '<p class="sg-lead">Canvas, WebGL, and audio values are one-way hashes computed by the browser; this site does not keep the raw render.</p>';
        } else {
            echo '<p class="sg-empty">No fingerprint payload was recorded. Rows collected before version 0.1.6 carry only the grouping hash.</p>';
        }
        Views::closeCard();

        // ---- Sessions ----
        Views::openCard('Sessions', 'Most recent 25');
        $sessionRows = [];
        foreach ((array) $detail['sessions'] as $session) {
            $sessionRows[] = [
                esc_html(self::date((string) $session['started_at'])),
                esc_html(self::when((string) $session['last_seen'])),
                esc_html(number_format_i18n((int) $session['pageviews'])),
                esc_html((string) $session['landing']),
                esc_html((string) $session['exit_path']),
                '<code>' . esc_html((string) $session['ip']) . '</code>',
                esc_html((string) $session['browser']),
            ];
        }
        Views::table(['Started', 'Last seen', 'Pages', 'Landing', 'Exit', 'Address', 'Browser'], $sessionRows);
        Views::closeCard();

        // ---- Activity ----
        Views::openCard('Recent activity', 'Most recent 50 events');
        $eventRows = [];
        foreach ($events as $event) {
            $eventRows[] = [
                esc_html(self::when((string) $event['ts'])),
                esc_html((string) $event['type']),
                esc_html((string) $event['path']),
                esc_html((string) $event['referrer']),
                '<code>' . esc_html((string) $event['ip']) . '</code>',
                esc_html((string) $event['browser']),
            ];
        }
        Views::table(['When', 'Type', 'Path', 'Referrer', 'Address', 'Browser'], $eventRows);
        Views::closeCard();

        // ---- Accounts ----
        Views::openCard('Signed-in accounts');
        $accountRows = [];
        foreach ((array) $detail['accounts'] as $account) {
            $user = get_userdata((int) $account['account_id']);
            $accountRows[] = [
                esc_html($user ? $user->user_login : '#' . (int) $account['account_id']),
                esc_html(self::when((string) $account['first_seen'])),
                esc_html(self::when((string) $account['last_seen'])),
            ];
        }
        Views::table(['Account', 'First seen', 'Last seen'], $accountRows, 'This browser has not been seen signed in.');
        Views::closeCard();
    }

    private static function list(Analytics $analytics, string $selected): void
    {
        $since = time() - 30 * 86400;
        $visitors = $analytics->recentVisitors($since, 100);

        Views::sectionTitle('Visitors', 'Every browser, with the address it connected from and the signals it reported.');

        Views::openCard('What is stored');
        echo '<ul class="sg-chips">';
        echo '<li>Address seen by the server</li>';
        echo '<li>User agent header</li>';
        echo '<li>Screen, time zone, language, CPU and memory hints</li>';
        echo '<li>Canvas, WebGL and audio hashes</li>';
        echo '<li>Signed-in account correlation</li>';
        echo '</ul>';
        echo '<p class="sg-lead">The visitor id is a random first-party value so one browser can be recognised across visits without a login. Address storage can be switched to a keyed hash or off in Settings.</p>';
        Views::closeCard();

        Views::openCard('Recent visitors', '30 days, most recent first');
        $rows = [];
        foreach ($visitors as $visitor) {
            $id = (string) $visitor['visitor'];
            $label = substr($id, 0, 12) . '…';
            $link = self::detailUrl($id);
            $rows[] = [
                '<a class="sg-visitor-link" href="' . esc_url($link) . '#visitors"><code>' . esc_html($label) . '</code></a>',
                $visitor['ip'] !== ''
                    ? '<code>' . esc_html($visitor['ip']) . '</code>'
                    : '<span class="sg-muted">not stored</span>',
                esc_html(trim(ucfirst($visitor['browser']) . ' / ' . $visitor['device'], ' /')),
                esc_html(number_format_i18n($visitor['pageviews'])),
                esc_html(self::when($visitor['last_seen'])),
            ];
        }
        Views::table(['Visitor', 'Address', 'Browser / device', 'Pageviews', 'Last seen'], $rows, 'No pageviews recorded in the last 30 days.');
        Views::closeCard();

        Views::openCard('Account correlation');
        $identities = Installer::tables()['identities'];
        $rows = (array) $GLOBALS['wpdb']->get_results(
            "SELECT i.account_id, COUNT(DISTINCT i.visitor) AS browsers, MAX(i.last_seen) AS last_seen
             FROM {$identities} i
             GROUP BY i.account_id ORDER BY last_seen DESC LIMIT 25",
            ARRAY_A
        );
        $out = [];
        foreach ($rows as $row) {
            $user = get_userdata((int) $row['account_id']);
            $out[] = [
                esc_html($user ? $user->user_login : '#' . (int) $row['account_id']),
                esc_html(number_format_i18n((int) $row['browsers'])),
                esc_html(self::when((string) $row['last_seen'])),
            ];
        }
        Views::table(['Account', 'Browsers', 'Last seen'], $out, 'No signed-in visitor has been correlated yet.');
        Views::closeCard();
    }

    /** One link per external lookup; each opens in a new tab. */
    private static function lookups(string $ip): string
    {
        $target = rawurlencode($ip);
        $links = [
            'ipinfo' => 'https://ipinfo.io/' . $target,
            'AbuseIPDB' => 'https://www.abuseipdb.com/check/' . $target,
            'Shodan' => 'https://www.shodan.io/host/' . $target,
            'RDAP' => 'https://rdap.org/ip/' . $target,
        ];
        $out = [];
        foreach ($links as $label => $url) {
            $out[] = '<a href="' . esc_url($url) . '" target="_blank" rel="noopener noreferrer">'
                . esc_html($label) . '</a>';
        }
        return implode(' · ', $out);
    }

    private static function selectedId(): string
    {
        if (!isset($_GET['sg_visitor'], $_GET['_wpnonce'])) {
            return '';
        }
        $nonce = sanitize_text_field(wp_unslash((string) $_GET['_wpnonce']));
        if (!wp_verify_nonce($nonce, self::DETAIL_ACTION)) {
            return '';
        }
        $raw = sanitize_text_field(wp_unslash((string) $_GET['sg_visitor']));
        return preg_match('/^[a-f0-9]{32}$/', $raw) === 1 ? $raw : '';
    }

    private static function listUrl(): string
    {
        return add_query_arg('page', Menu::OVERVIEW, admin_url('admin.php')) . '#visitors';
    }

    private static function detailUrl(string $id): string
    {
        return wp_nonce_url(
            add_query_arg(
                ['page' => Menu::OVERVIEW, 'sg_visitor' => $id],
                admin_url('admin.php')
            ),
            self::DETAIL_ACTION
        );
    }

    private static function date(string $utc): string
    {
        $ts = strtotime($utc . ' UTC');
        return $ts ? wp_date('M j, Y H:i', $ts) : '—';
    }

    private static function when(string $utc): string
    {
        $ts = strtotime($utc . ' UTC');
        if (!$ts) {
            return '—';
        }
        return sprintf('%s ago', human_time_diff($ts, time()));
    }
}
