<?php
declare(strict_types=1);

namespace SiteGuard\Wp;

use SiteGuard\Core\Profile\Fingerprint;

/**
 * Read-only aggregate queries for the dashboard.
 *
 * Browser-sourced rows are reported separately from server-sourced rows. A
 * forged beacon can inflate the "reported" column, which is why the overview
 * shows both and labels which one enforcement actually uses.
 */
final class Analytics
{
    public function __construct(private \wpdb $db)
    {
    }

    private function table(string $key): string
    {
        return Installer::tables()[$key];
    }

    public function totals(int $since): array
    {
        $events = $this->table('events');
        $sessions = $this->table('sessions');
        $incidents = $this->table('incidents');
        $sinceSql = gmdate('Y-m-d H:i:s', $since);

        return [
            'reported_pageviews' => (int) $this->db->get_var($this->db->prepare(
                "SELECT COUNT(*) FROM $events WHERE source = 'browser' AND type = 'pageview' AND ts >= %s",
                $sinceSql
            )),
            'server_requests' => (int) $this->db->get_var($this->db->prepare(
                "SELECT COUNT(*) FROM $events WHERE source = 'server' AND ts >= %s",
                $sinceSql
            )),
            'visitors' => (int) $this->db->get_var($this->db->prepare(
                "SELECT COUNT(DISTINCT visitor) FROM $events WHERE source = 'browser' AND visitor <> '' AND ts >= %s",
                $sinceSql
            )),
            'sessions' => (int) $this->db->get_var($this->db->prepare(
                "SELECT COUNT(*) FROM $sessions WHERE started_at >= %s",
                $sinceSql
            )),
            'incidents' => (int) $this->db->get_var($this->db->prepare(
                "SELECT COUNT(*) FROM $incidents WHERE ts >= %s",
                $sinceSql
            )),
            'active_blocks' => Config::blocks()->countActive(time()),
        ];
    }

    /** @return list<array{day:string,pageviews:int,visitors:int}> */
    public function daily(int $since, int $days = 14): array
    {
        $events = $this->table('events');
        $rows = (array) $this->db->get_results($this->db->prepare(
            "SELECT DATE(ts) AS day, COUNT(*) AS pageviews, COUNT(DISTINCT visitor) AS visitors
             FROM $events
             WHERE source = 'browser' AND type = 'pageview' AND ts >= %s
             GROUP BY DATE(ts) ORDER BY day ASC",
            gmdate('Y-m-d H:i:s', $since)
        ), ARRAY_A);

        $byDay = [];
        foreach ($rows as $row) {
            $byDay[(string) $row['day']] = [
                'day' => (string) $row['day'],
                'pageviews' => (int) $row['pageviews'],
                'visitors' => (int) $row['visitors'],
            ];
        }

        $out = [];
        $start = strtotime('today UTC') - ($days - 1) * 86400;
        for ($i = 0; $i < $days; $i++) {
            $day = gmdate('Y-m-d', $start + $i * 86400);
            $out[] = $byDay[$day] ?? ['day' => $day, 'pageviews' => 0, 'visitors' => 0];
        }
        return $out;
    }

    /** @return list<array{path:string,views:int}> */
    public function topPaths(int $since, int $limit = 10): array
    {
        $events = $this->table('events');
        $rows = (array) $this->db->get_results($this->db->prepare(
            "SELECT path, COUNT(*) AS views FROM $events
             WHERE source = 'browser' AND type = 'pageview' AND ts >= %s
             GROUP BY path ORDER BY views DESC LIMIT %d",
            gmdate('Y-m-d H:i:s', $since),
            max(1, min(50, $limit))
        ), ARRAY_A);
        return array_map(
            static fn (array $r): array => ['path' => (string) $r['path'], 'views' => (int) $r['views']],
            $rows
        );
    }

    /** @return list<array{referrer:string,views:int}> */
    public function topReferrers(int $since, int $limit = 8): array
    {
        $events = $this->table('events');
        $rows = (array) $this->db->get_results($this->db->prepare(
            "SELECT referrer, COUNT(*) AS views FROM $events
             WHERE source = 'browser' AND type = 'pageview' AND referrer <> '' AND ts >= %s
             GROUP BY referrer ORDER BY views DESC LIMIT %d",
            gmdate('Y-m-d H:i:s', $since),
            max(1, min(50, $limit))
        ), ARRAY_A);
        return array_map(
            static fn (array $r): array => ['referrer' => (string) $r['referrer'], 'views' => (int) $r['views']],
            $rows
        );
    }

    /** @return list<array{device:string,views:int}> */
    public function devices(int $since): array
    {
        $events = $this->table('events');
        $rows = (array) $this->db->get_results($this->db->prepare(
            "SELECT device, COUNT(*) AS views FROM $events
             WHERE source = 'browser' AND type = 'pageview' AND ts >= %s
             GROUP BY device ORDER BY views DESC",
            gmdate('Y-m-d H:i:s', $since)
        ), ARRAY_A);
        return array_map(
            static fn (array $r): array => ['device' => (string) $r['device'], 'views' => (int) $r['views']],
            $rows
        );
    }

    /** @return list<array<string,mixed>> */
    public function coverage(): array
    {
        $table = $this->table('coverage');
        return (array) $this->db->get_results(
            "SELECT class, status, reason, tested_at FROM $table ORDER BY class ASC",
            ARRAY_A
        );
    }

    /** Distinct correlated browsers seen for an account. */
    public function identitiesFor(int $accountId): int
    {
        $table = $this->table('identities');
        return (int) $this->db->get_var($this->db->prepare(
            "SELECT COUNT(DISTINCT visitor) FROM $table WHERE account_id = %d",
            $accountId
        ));
    }

    /**
     * Visitors active in the window, with the latest network and browser
     * values so the list can be read without opening each row.
     *
     * @return list<array<string,mixed>>
     */
    public function recentVisitors(int $since, int $limit = 100): array
    {
        $events = $this->table('events');
        $visitors = $this->table('visitors');
        $rows = (array) $this->db->get_results($this->db->prepare(
            "SELECT visitor, COUNT(*) AS pageviews, MAX(ts) AS last_seen
             FROM $events
             WHERE source = 'browser' AND type = 'pageview' AND visitor <> '' AND ts >= %s
             GROUP BY visitor ORDER BY last_seen DESC LIMIT %d",
            gmdate('Y-m-d H:i:s', $since),
            max(1, min(200, $limit))
        ), ARRAY_A);
        if (!$rows) {
            return [];
        }

        $ids = array_map(static fn (array $r): string => (string) $r['visitor'], $rows);
        $placeholders = implode(',', array_fill(0, count($ids), '%s'));
        $latest = [];
        foreach ((array) $this->db->get_results($this->db->prepare(
            "SELECT id, first_seen, sessions, ip, ua, device, browser, last_path, profile
             FROM $visitors WHERE id IN ($placeholders)",
            ...$ids
        ), ARRAY_A) as $row) {
            $latest[(string) $row['id']] = $row;
        }

        return array_map(static function (array $r) use ($latest): array {
            $id = (string) $r['visitor'];
            $extra = $latest[$id] ?? [];
            $profile = [];
            $json = (string) ($extra['profile'] ?? '');
            if ($json !== '') {
                $decoded = json_decode($json, true);
                if (is_array($decoded)) {
                    $profile = $decoded;
                }
            }
            return [
                'visitor' => $id,
                'pageviews' => (int) $r['pageviews'],
                'last_seen' => (string) $r['last_seen'],
                'first_seen' => (string) ($extra['first_seen'] ?? ''),
                'sessions' => (int) ($extra['sessions'] ?? 0),
                'ip' => (string) ($extra['ip'] ?? ''),
                'ua' => (string) ($extra['ua'] ?? ''),
                'device' => (string) ($extra['device'] ?? ''),
                'browser' => (string) ($extra['browser'] ?? ''),
                'last_path' => (string) ($extra['last_path'] ?? ''),
                'profile' => $profile,
                'verdict' => Fingerprint::verdict($profile),
            ];
        }, $rows);
    }

    /**
     * Everything recorded for one visitor id: the rollup row, their sessions,
     * their recent events, and any accounts the browser signed in to. Empty
     * arrays rather than nulls so the caller never has to null-check a list.
     *
     * @return array<string,mixed>|null
     */
    public function visitorDetail(string $visitorId): ?array
    {
        $visitors = $this->table('visitors');
        $sessions = $this->table('sessions');
        $events = $this->table('events');
        $identities = $this->table('identities');

        $row = $this->db->get_row($this->db->prepare(
            "SELECT id, first_seen, last_seen, sessions, pageviews, ip, ua, profile, last_path
             FROM $visitors WHERE id = %s",
            $visitorId
        ), ARRAY_A);
        if (!$row) {
            return null;
        }

        $sessionRows = (array) $this->db->get_results($this->db->prepare(
            "SELECT id, started_at, last_seen, pageviews, landing, exit_path, device, browser, ip, ua
             FROM $sessions WHERE visitor = %s ORDER BY last_seen DESC LIMIT 25",
            $visitorId
        ), ARRAY_A);

        $eventRows = (array) $this->db->get_results($this->db->prepare(
            "SELECT ts, type, path, referrer, device, browser, ip, ua, profile, meta
             FROM $events WHERE visitor = %s ORDER BY id DESC LIMIT 50",
            $visitorId
        ), ARRAY_A);

        $accounts = (array) $this->db->get_results($this->db->prepare(
            "SELECT account_id, first_seen, last_seen FROM $identities
             WHERE visitor = %s ORDER BY last_seen DESC",
            $visitorId
        ), ARRAY_A);

        $distinct = $this->db->get_row($this->db->prepare(
            "SELECT COUNT(DISTINCT ip) AS ips, COUNT(DISTINCT profile) AS profiles
             FROM $events WHERE visitor = %s AND ip <> ''",
            $visitorId
        ), ARRAY_A);

        return [
            'visitor' => $row,
            'sessions' => array_map([self::class, 'withDecodedProfile'], $sessionRows),
            'events' => array_map([self::class, 'withDecodedProfile'], $eventRows),
            'accounts' => array_map(static fn (array $a): array => [
                'account_id' => (int) $a['account_id'],
                'first_seen' => (string) $a['first_seen'],
                'last_seen' => (string) $a['last_seen'],
            ], $accounts),
            'distinct_ips' => (int) ($distinct['ips'] ?? 0),
            'distinct_profiles' => (int) ($distinct['profiles'] ?? 0),
        ];
    }

    /**
     * Turns the stored profile JSON into an array for display. A row written
     * before the profile column existed, or a malformed one, becomes [].
     *
     * @param array<string,mixed> $row
     * @return array<string,mixed>
     */
    private static function withDecodedProfile(array $row): array
    {
        $decoded = [];
        if (isset($row['profile']) && is_string($row['profile']) && $row['profile'] !== '') {
            $value = json_decode($row['profile'], true);
            if (is_array($value)) {
                $decoded = $value;
            }
        }
        $row['profile'] = $decoded;
        return $row;
    }
}
