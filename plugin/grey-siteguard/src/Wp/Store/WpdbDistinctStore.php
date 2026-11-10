<?php
declare(strict_types=1);

namespace SiteGuard\Wp\Store;

use SiteGuard\Core\Store\Distinct;
use SiteGuard\Wp\Installer;

/**
 * Distinct-path tracking. INSERT IGNORE keeps the unique key authoritative, so
 * two concurrent requests for the same path count once.
 */
final class WpdbDistinctStore implements Distinct
{
    public function __construct(private \wpdb $db, private ?string $table = null)
    {
        $this->table = $table ?? Installer::tables()['distinct'];
    }


    public function touch(string $subject, string $pathHash, int $windowStart): bool
    {
        $this->db->query($this->db->prepare(
            "INSERT IGNORE INTO {$this->table} (subject, path_hash, window_start) VALUES (%s, %s, %d)",
            $subject,
            $pathHash,
            $windowStart
        ));
        return $this->db->rows_affected > 0;
    }

    public function count(string $subject, int $since): int
    {
        return (int) $this->db->get_var($this->db->prepare(
            "SELECT COUNT(*) FROM {$this->table} WHERE subject = %s AND window_start >= %d",
            $subject,
            $since
        ));
    }

    public function prune(int $olderThan): int
    {
        $this->db->query($this->db->prepare(
            "DELETE FROM {$this->table} WHERE window_start < %d LIMIT 2000",
            $olderThan
        ));
        return (int) $this->db->rows_affected;
    }
}
