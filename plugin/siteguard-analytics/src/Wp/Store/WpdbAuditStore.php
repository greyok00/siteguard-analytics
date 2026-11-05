<?php
declare(strict_types=1);

namespace SiteGuard\Wp\Store;

use SiteGuard\Core\Store\Audit;
use SiteGuard\Wp\Installer;

/**
 * wpdb-backed audit log. One insert per privileged action; reads are limited
 * and ordered newest first, and retention prunes in bounded batches.
 */
final class WpdbAuditStore implements Audit
{
    public function __construct(private \wpdb $db, private ?string $table = null)
    {
        $this->table = $table ?? Installer::tables()['audit'];
    }


    public function record(int $actorId, string $action, string $target, array $details, int $now): int
    {
        $json = function_exists('wp_json_encode')
            ? (string) wp_json_encode($details)
            : (string) json_encode($details);

        $this->db->insert($this->table, [
            'ts' => gmdate('Y-m-d H:i:s', $now),
            'actor_id' => max(0, $actorId),
            'action' => substr($action, 0, 64),
            'target' => substr($target, 0, 191),
            'details' => $json,
        ]);
        return (int) $this->db->insert_id;
    }

    public function recent(int $limit = 100, int $offset = 0): array
    {
        return (array) $this->db->get_results($this->db->prepare(
            "SELECT id, ts, actor_id, action, target, details
             FROM {$this->table} ORDER BY id DESC LIMIT %d OFFSET %d",
            max(1, min(200, $limit)),
            max(0, $offset)
        ), ARRAY_A);
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
