<?php
declare(strict_types=1);

namespace SiteGuard\Wp\Store;

use SiteGuard\Core\Store\Blocks;
use SiteGuard\Wp\Installer;

/**
 * Temporary blocks keyed by subject (an address prefix or a pseudonymous
 * browser). Expired rows are inert on read and deleted by retention.
 */
final class WpdbBlockStore implements Blocks
{
    private const COLUMNS = 'id, subject, scope, reason, rule, evidence, created_at, expires_at, created_by, lifted_at';

    public function __construct(private \wpdb $db, private ?string $table = null)
    {
        $this->table = $table ?? Installer::tables()['blocks'];
    }


    public function active(string $subject, int $now): ?array
    {
        $row = $this->db->get_row($this->db->prepare(
            "SELECT " . self::COLUMNS . " FROM {$this->table}
             WHERE subject = %s AND lifted_at IS NULL AND expires_at > %s
             ORDER BY id DESC LIMIT 1",
            $subject,
            gmdate('Y-m-d H:i:s', $now)
        ), ARRAY_A);
        return $row ?: null;
    }

    public function add(
        string $subject,
        string $scope,
        string $reason,
        string $rule,
        array $evidence,
        int $now,
        int $expiresAt,
        string $createdBy = 'system'
    ): int {
        if ($this->active($subject, $now) !== null) {
            return 0;
        }
        $json = function_exists('wp_json_encode')
            ? (string) wp_json_encode($evidence)
            : (string) json_encode($evidence);

        // A leftover expired row for the same subject is overwritten rather
        // than duplicated; the unique key allows exactly one row.
        $this->db->query($this->db->prepare(
            "INSERT INTO {$this->table}
                (subject, scope, reason, rule, evidence, created_at, expires_at, created_by, lifted_at)
             VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NULL)
             ON DUPLICATE KEY UPDATE
                scope = VALUES(scope), reason = VALUES(reason), rule = VALUES(rule),
                evidence = VALUES(evidence), created_at = VALUES(created_at),
                expires_at = VALUES(expires_at), created_by = VALUES(created_by),
                lifted_at = NULL",
            $subject,
            $scope,
            $reason,
            $rule,
            $json,
            gmdate('Y-m-d H:i:s', $now),
            gmdate('Y-m-d H:i:s', $expiresAt),
            $createdBy
        ));
        // insert_id is 0 on the ON DUPLICATE branch, so read the row back.
        return (int) $this->db->get_var($this->db->prepare(
            "SELECT id FROM {$this->table} WHERE subject = %s",
            $subject
        ));
    }

    public function lift(string $subject, int $now): bool
    {
        $this->db->query($this->db->prepare(
            "UPDATE {$this->table} SET lifted_at = %s
             WHERE subject = %s AND lifted_at IS NULL AND expires_at > %s",
            gmdate('Y-m-d H:i:s', $now),
            $subject,
            gmdate('Y-m-d H:i:s', $now)
        ));
        return $this->db->rows_affected > 0;
    }

    public function prune(int $now, int $limit = 200): int
    {
        $limit = max(1, min(2000, $limit));
        $this->db->query($this->db->prepare(
            "DELETE FROM {$this->table} WHERE expires_at <= %s LIMIT %d",
            gmdate('Y-m-d H:i:s', $now - 86400),
            $limit
        ));
        return (int) $this->db->rows_affected;
    }

    public function listActive(int $now, int $limit = 100, int $offset = 0): array
    {
        return (array) $this->db->get_results($this->db->prepare(
            "SELECT " . self::COLUMNS . " FROM {$this->table}
             WHERE lifted_at IS NULL AND expires_at > %s
             ORDER BY created_at DESC LIMIT %d OFFSET %d",
            gmdate('Y-m-d H:i:s', $now),
            max(1, min(500, $limit)),
            max(0, $offset)
        ), ARRAY_A);
    }

    public function countActive(int $now): int
    {
        return (int) $this->db->get_var($this->db->prepare(
            "SELECT COUNT(*) FROM {$this->table} WHERE lifted_at IS NULL AND expires_at > %s",
            gmdate('Y-m-d H:i:s', $now)
        ));
    }

    public function recentCount(string $subject, int $since): int
    {
        return (int) $this->db->get_var($this->db->prepare(
            "SELECT COUNT(*) FROM {$this->table} WHERE subject = %s AND created_at >= %s",
            $subject,
            gmdate('Y-m-d H:i:s', $since)
        ));
    }
}
