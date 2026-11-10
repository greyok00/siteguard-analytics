<?php
declare(strict_types=1);

namespace SiteGuard\Wp\Store;

use SiteGuard\Core\Store\Incidents;
use SiteGuard\Wp\Installer;

/**
 * wpdb-backed incident records. One row per escalation event, with the rule
 * and the evidence that produced it stored as JSON.
 */
final class WpdbIncidentStore implements Incidents
{
    public function __construct(private \wpdb $db, private ?string $table = null)
    {
        $this->table = $table ?? Installer::tables()['incidents'];
    }


    public function record(
        string $subject,
        string $rule,
        string $severity,
        array $evidence,
        int $requestCount,
        int $blockId,
        int $now
    ): int {
        $json = function_exists('wp_json_encode')
            ? (string) wp_json_encode($evidence)
            : (string) json_encode($evidence);

        $this->db->insert($this->table, [
            'ts' => gmdate('Y-m-d H:i:s', $now),
            'subject' => substr($subject, 0, 48),
            'rule' => substr($rule, 0, 64),
            'severity' => in_array($severity, ['low', 'medium', 'high'], true) ? $severity : 'medium',
            'evidence' => $json,
            'request_count' => max(0, $requestCount),
            'block_id' => max(0, $blockId),
        ]);
        return (int) $this->db->insert_id;
    }

    public function recent(int $limit = 50, int $offset = 0): array
    {
        return (array) $this->db->get_results($this->db->prepare(
            "SELECT id, ts, subject, rule, severity, evidence, request_count, block_id, resolved_at
             FROM {$this->table} ORDER BY id DESC LIMIT %d OFFSET %d",
            max(1, min(200, $limit)),
            max(0, $offset)
        ), ARRAY_A);
    }

    public function countSince(int $since): int
    {
        return (int) $this->db->get_var($this->db->prepare(
            "SELECT COUNT(*) FROM {$this->table} WHERE ts >= %s",
            gmdate('Y-m-d H:i:s', $since)
        ));
    }

    public function countFor(string $subject, int $since): int
    {
        return (int) $this->db->get_var($this->db->prepare(
            "SELECT COUNT(*) FROM {$this->table} WHERE subject = %s AND ts >= %s",
            $subject,
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
