<?php
declare(strict_types=1);

namespace SiteGuard\Wp\Store;

use SiteGuard\Core\Store\People;
use SiteGuard\Wp\Installer;

/**
 * Session and visitor rollups. All timestamps are UTC; the dashboard converts
 * for display using the site timezone.
 */
final class WpdbPeopleStore implements People
{
    public function __construct(
        private \wpdb $db,
        private ?array $tables = null
    ) {
        $this->tables = $tables ?? Installer::tables();
    }


    public function touchSession(string $sessionId, array $meta, int $now, bool $newPageview): void
    {
        $table = $this->tables['sessions'];
        $ts = gmdate('Y-m-d H:i:s', $now);
        $increment = $newPageview ? 1 : 0;

        $this->db->query($this->db->prepare(
            "INSERT INTO {$table}
                (id, visitor, account_id, started_at, last_seen, pageviews, landing, exit_path, device, browser, ip, ua, ip_hash)
             VALUES (%s, %s, %d, %s, %s, %d, %s, %s, %s, %s, %s, %s, %s)
             ON DUPLICATE KEY UPDATE
                last_seen = VALUES(last_seen),
                pageviews = pageviews + %d,
                account_id = IF(VALUES(account_id) > 0, VALUES(account_id), account_id),
                ip = IF(VALUES(ip) <> '', VALUES(ip), ip),
                ua = IF(VALUES(ua) <> '', VALUES(ua), ua)",
            $sessionId,
            (string) ($meta['visitor'] ?? ''),
            (int) ($meta['account_id'] ?? 0),
            $ts,
            $ts,
            $increment,
            (string) ($meta['landing'] ?? ''),
            '',
            (string) ($meta['device'] ?? ''),
            (string) ($meta['browser'] ?? ''),
            (string) ($meta['ip'] ?? ''),
            (string) ($meta['ua'] ?? ''),
            (string) ($meta['ip_hash'] ?? ''),
            $increment
        ));
    }

    public function closeSession(string $sessionId, string $exitPath, int $now): void
    {
        $table = $this->tables['sessions'];
        $this->db->query($this->db->prepare(
            "UPDATE {$table} SET exit_path = %s, last_seen = GREATEST(last_seen, %s) WHERE id = %s",
            substr($exitPath, 0, 255),
            gmdate('Y-m-d H:i:s', $now),
            $sessionId
        ));
    }

    public function touchVisitor(string $visitorId, int $now, bool $newSession, bool $newPageview, array $meta = []): void
    {
        $table = $this->tables['visitors'];
        $ts = gmdate('Y-m-d H:i:s', $now);
        $sessions = $newSession ? 1 : 0;
        $views = $newPageview ? 1 : 0;
        $profile = isset($meta['profile']) && is_string($meta['profile']) && $meta['profile'] !== ''
            ? $meta['profile']
            : null;

        $this->db->query($this->db->prepare(
            "INSERT INTO {$table} (id, first_seen, last_seen, sessions, pageviews, ip, ua, profile, last_path)
             VALUES (%s, %s, %s, %d, %d, %s, %s, %s, %s)
             ON DUPLICATE KEY UPDATE
                last_seen = VALUES(last_seen),
                sessions = sessions + %d,
                pageviews = pageviews + %d,
                ip = IF(VALUES(ip) <> '', VALUES(ip), ip),
                ua = IF(VALUES(ua) <> '', VALUES(ua), ua),
                profile = IF(VALUES(profile) IS NOT NULL, VALUES(profile), profile),
                last_path = IF(VALUES(last_path) <> '', VALUES(last_path), last_path)",
            $visitorId,
            $ts,
            $ts,
            $sessions,
            $views,
            substr((string) ($meta['ip'] ?? ''), 0, 45),
            substr((string) ($meta['ua'] ?? ''), 0, 400),
            $profile,
            substr((string) ($meta['last_path'] ?? ''), 0, 255),
            $sessions,
            $views
        ));
    }

    /**
     * The stored profile JSON for one visitor, decoded. Silence laws: an
     * unknown id, an empty column, or JSON that does not decode to an array
     * all answer [] — absence of evidence is clean, never a lie.
     * @return array<string,mixed>
     */
    public function profileFor(string $visitorId): array
    {
        if ($visitorId === '' || !preg_match('/^[0-9a-f]{32}$/', $visitorId)) {
            return [];
        }
        $table = $this->tables['visitors'];
        $json = (string) $this->db->get_var($this->db->prepare(
            "SELECT profile FROM {$table} WHERE id = %s",
            $visitorId
        ));
        if ($json === '') {
            return [];
        }
        $decoded = json_decode($json, true);
        return is_array($decoded) ? $decoded : [];
    }

    public function linkIdentity(string $visitorId, int $accountId, int $now): void
    {
        if ($visitorId === '' || $accountId < 1) {
            return;
        }
        $table = $this->tables['identities'];
        $ts = gmdate('Y-m-d H:i:s', $now);
        $this->db->query($this->db->prepare(
            "INSERT INTO {$table} (visitor, account_id, first_seen, last_seen)
             VALUES (%s, %d, %s, %s)
             ON DUPLICATE KEY UPDATE last_seen = VALUES(last_seen)",
            $visitorId,
            $accountId,
            $ts,
            $ts
        ));
    }

    public function countSessions(int $since, int $until): int
    {
        $table = $this->tables['sessions'];
        return (int) $this->db->get_var($this->db->prepare(
            "SELECT COUNT(*) FROM {$table} WHERE started_at >= %s AND started_at < %s",
            gmdate('Y-m-d H:i:s', $since),
            gmdate('Y-m-d H:i:s', $until)
        ));
    }

    public function pruneBefore(int $before): int
    {
        $cut = gmdate('Y-m-d H:i:s', $before);
        $total = 0;
        foreach (['sessions', 'visitors'] as $key) {
            $table = $this->tables[$key];
            $this->db->query($this->db->prepare(
                "DELETE FROM {$table} WHERE last_seen < %s LIMIT 2000",
                $cut
            ));
            $total += (int) $this->db->rows_affected;
        }
        return $total;
    }
}
