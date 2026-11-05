<?php
declare(strict_types=1);

namespace SiteGuard\Wp\Store;

use SiteGuard\Core\Store\Events;
use SiteGuard\Wp\Installer;

/**
 * Append-only event rows. Inserts are INSERT IGNORE so a replayed beacon with
 * the same dedupe key is dropped by the unique index rather than by PHP.
 */
final class WpdbEventStore implements Events
{
    private const COLUMNS = 'id, ts, source, type, visitor, session, account_id, path,
        referrer, ua_hash, device, browser, ip, ua, profile, meta, ip_hash';

    public function __construct(private \wpdb $db, private ?string $table = null)
    {
        $this->table = $table ?? Installer::tables()['events'];
    }


    public function insert(array $row): int
    {
        $meta = $row['meta'] ?? null;
        if (is_array($meta)) {
            $meta = function_exists('wp_json_encode') ? wp_json_encode($meta) : json_encode($meta);
        }
        $dedupe = isset($row['dedupe']) && $row['dedupe'] !== '' ? (string) $row['dedupe'] : null;

        $args = [
            (string) ($row['ts'] ?? gmdate('Y-m-d H:i:s')),
            (string) ($row['source'] ?? 'browser'),
            (string) ($row['type'] ?? 'pageview'),
            (string) ($row['visitor'] ?? ''),
            (string) ($row['session'] ?? ''),
            (int) ($row['account_id'] ?? 0),
            (string) ($row['path'] ?? ''),
            (string) ($row['referrer'] ?? ''),
            (string) ($row['ua_hash'] ?? ''),
            (string) ($row['device'] ?? ''),
            (string) ($row['browser'] ?? ''),
            substr((string) ($row['ip'] ?? ''), 0, 45),
            substr((string) ($row['ua'] ?? ''), 0, 400),
            (string) ($row['profile'] ?? ''),
            $meta === null ? '' : (string) $meta,
        ];
        $hash = (string) ($row['ip_hash'] ?? '');

        if ($dedupe === null) {
            // NULL is a distinct value in a unique index; '' is not, so the
            // literal must be used rather than a placeholder bound to null.
            $sql = "INSERT IGNORE INTO {$this->table}
                (ts, source, type, visitor, session, account_id, path, referrer,
                 ua_hash, device, browser, ip, ua, profile, meta, dedupe, ip_hash)
                VALUES (%s, %s, %s, %s, %s, %d, %s, %s, %s, %s, %s, %s, %s, %s, %s, NULL, %s)";
            $args[] = $hash;
        } else {
            $sql = "INSERT IGNORE INTO {$this->table}
                (ts, source, type, visitor, session, account_id, path, referrer,
                 ua_hash, device, browser, ip, ua, profile, meta, dedupe, ip_hash)
                VALUES (%s, %s, %s, %s, %s, %d, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)";
            $args[] = $dedupe;
            $args[] = $hash;
        }

        $this->db->query($this->db->prepare($sql, ...$args));
        return $this->db->rows_affected > 0 ? (int) $this->db->insert_id : 0;
    }

    public function recent(int $limit = 50, string $source = ''): array
    {
        $limit = max(1, min(200, $limit));
        if ($source !== '') {
            $rows = $this->db->get_results($this->db->prepare(
                "SELECT " . self::COLUMNS . " FROM {$this->table}
                 WHERE source = %s ORDER BY id DESC LIMIT %d",
                $source,
                $limit
            ), ARRAY_A);
            return (array) $rows;
        }
        return (array) $this->db->get_results($this->db->prepare(
            "SELECT " . self::COLUMNS . " FROM {$this->table} ORDER BY id DESC LIMIT %d",
            $limit
        ), ARRAY_A);
    }

    public function countSince(int $since, string $source = ''): int
    {
        if ($source !== '') {
            return (int) $this->db->get_var($this->db->prepare(
                "SELECT COUNT(*) FROM {$this->table} WHERE ts >= %s AND source = %s",
                gmdate('Y-m-d H:i:s', $since),
                $source
            ));
        }
        return (int) $this->db->get_var($this->db->prepare(
            "SELECT COUNT(*) FROM {$this->table} WHERE ts >= %s",
            gmdate('Y-m-d H:i:s', $since)
        ));
    }

    public function pruneBefore(int $before): int
    {
        $this->db->query($this->db->prepare(
            "DELETE FROM {$this->table} WHERE ts < %s LIMIT 2000",
            gmdate('Y-m-d H:i:s', $before)
        ));
        return (int) $this->db->rows_affected;
    }
}
