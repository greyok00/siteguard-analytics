<?php
declare(strict_types=1);

namespace SiteGuard\Wp\Store;

use SiteGuard\Core\Store\Counters;
use SiteGuard\Wp\Installer;

/**
 * Fixed-window counters backed by one atomic upsert.
 *
 * The SELECT after the write can only over-report under a race, which fails
 * closed (a legitimate request at the boundary is throttled for one window) —
 * never the reverse.
 */
final class WpdbCounterStore implements Counters
{
    public function __construct(private \wpdb $db, private ?string $table = null)
    {
        $this->table = $table ?? Installer::tables()['counters'];
    }


    public function hit(string $key, int $ttlSeconds): int
    {
        $ttl = max(1, $ttlSeconds);
        $now = gmdate('Y-m-d H:i:s');
        $expires = gmdate('Y-m-d H:i:s', time() + $ttl);

        // An expired row for the same key restarts at 1 instead of inheriting
        // the old window's total. Assignments run left to right, so `n` is
        // evaluated against the previous `expires_at` before it is replaced.
        $sql = $this->db->prepare(
            "INSERT INTO {$this->table} (k, n, expires_at) VALUES (%s, 1, %s)
             ON DUPLICATE KEY UPDATE
                n = IF(expires_at <= %s, 1, n + 1),
                expires_at = %s",
            $key,
            $expires,
            $now,
            $expires
        );
        $this->db->query($sql);

        return (int) $this->db->get_var($this->db->prepare(
            "SELECT n FROM {$this->table} WHERE k = %s AND expires_at > %s",
            $key,
            $now
        ));
    }

    public function get(string $key): int
    {
        return (int) $this->db->get_var($this->db->prepare(
            "SELECT n FROM {$this->table} WHERE k = %s AND expires_at > %s",
            $key,
            gmdate('Y-m-d H:i:s')
        ));
    }

    public function prune(int $limit = 500): int
    {
        $limit = max(1, min(5000, $limit));
        $rows = (int) $this->db->get_var($this->db->prepare(
            "SELECT COUNT(*) FROM {$this->table} WHERE expires_at <= %s",
            gmdate('Y-m-d H:i:s')
        ));
        if ($rows < 1) {
            return 0;
        }
        $this->db->query($this->db->prepare(
            "DELETE FROM {$this->table} WHERE expires_at <= %s LIMIT %d",
            gmdate('Y-m-d H:i:s'),
            $limit
        ));
        return min($rows, $limit);
    }
}
