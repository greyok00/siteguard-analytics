<?php
declare(strict_types=1);

namespace SiteGuard\Slim;

use PDO;
use SiteGuard\Core\Store\Blocks;
use SiteGuard\Core\Store\Counters;
use SiteGuard\Core\Store\Distinct;
use SiteGuard\Core\Store\Incidents;

/**
 * PDO storage for the standalone middleware.
 *
 * Each interface is a separate class because the interfaces declare methods
 * with different signatures (`prune` means two different things); one class
 * cannot implement both.
 *
 * MySQL and SQLite are both supported, with the two divergent upserts written
 * as separate SQL.
 */
abstract class PdoBase
{
    protected bool $sqlite;

    public function __construct(protected PDO $pdo)
    {
        $this->sqlite = $pdo->getAttribute(PDO::ATTR_DRIVER_NAME) === 'sqlite';
    }

    protected function exec(string $sql, array $params): void
    {
        $this->pdo->prepare($sql)->execute($params);
    }

    /** @return list<array<string,mixed>> */
    protected function all(string $sql, array $params = []): array
    {
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);
        return (array) $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    protected function scalar(string $sql, array $params = []): mixed
    {
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetchColumn();
    }
}

final class PdoCounters extends PdoBase implements Counters
{
    public function hit(string $key, int $ttlSeconds): int
    {
        $now = gmdate('Y-m-d H:i:s');
        $expires = gmdate('Y-m-d H:i:s', time() + max(1, $ttlSeconds));

        $sql = $this->sqlite
            ? 'INSERT INTO sg_counters (k, n, expires_at) VALUES (:k, 1, :exp)
               ON CONFLICT(k) DO UPDATE SET
                 n = CASE WHEN expires_at <= :now THEN 1 ELSE n + 1 END,
                 expires_at = :exp'
            : 'INSERT INTO sg_counters (k, n, expires_at) VALUES (:k, 1, :exp)
               ON DUPLICATE KEY UPDATE
                 n = IF(expires_at <= :now, 1, n + 1),
                 expires_at = :exp2';

        $params = [':k' => $key, ':exp' => $expires, ':now' => $now];
        if (!$this->sqlite) {
            $params[':exp2'] = $expires;
        }
        $this->exec($sql, $params);

        return (int) $this->scalar(
            'SELECT n FROM sg_counters WHERE k = :k AND expires_at > :now',
            [':k' => $key, ':now' => $now]
        );
    }

    public function get(string $key): int
    {
        return (int) $this->scalar(
            'SELECT n FROM sg_counters WHERE k = :k AND expires_at > :now',
            [':k' => $key, ':now' => gmdate('Y-m-d H:i:s')]
        );
    }

    public function prune(int $limit = 500): int
    {
        $limit = max(1, min(5000, $limit));
        $sql = $this->sqlite
            ? 'DELETE FROM sg_counters WHERE rowid IN
                 (SELECT rowid FROM sg_counters WHERE expires_at <= :now LIMIT :limit)'
            : 'DELETE FROM sg_counters WHERE expires_at <= :now LIMIT :limit';
        $stmt = $this->pdo->prepare($sql);
        $stmt->bindValue(':now', gmdate('Y-m-d H:i:s'));
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->rowCount();
    }
}

final class PdoDistinct extends PdoBase implements Distinct
{
    public function touch(string $subject, string $pathHash, int $windowStart): bool
    {
        $sql = $this->sqlite
            ? 'INSERT INTO sg_distinct (subject, path_hash, window_start) VALUES (:s, :p, :w)
               ON CONFLICT DO NOTHING'
            : 'INSERT IGNORE INTO sg_distinct (subject, path_hash, window_start) VALUES (:s, :p, :w)';
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([':s' => $subject, ':p' => $pathHash, ':w' => $windowStart]);
        return $stmt->rowCount() > 0;
    }

    public function count(string $subject, int $since): int
    {
        return (int) $this->scalar(
            'SELECT COUNT(*) FROM sg_distinct WHERE subject = :s AND window_start >= :w',
            [':s' => $subject, ':w' => $since]
        );
    }

    public function prune(int $olderThan): int
    {
        $stmt = $this->pdo->prepare(
            'DELETE FROM sg_distinct WHERE window_start < :cut'
        );
        $stmt->execute([':cut' => $olderThan]);
        return $stmt->rowCount();
    }
}

final class PdoBlocks extends PdoBase implements Blocks
{
    public function active(string $subject, int $now): ?array
    {
        $rows = $this->all(
            'SELECT * FROM sg_blocks WHERE subject = :s AND lifted_at IS NULL AND expires_at > :now
             ORDER BY id DESC LIMIT 1',
            [':s' => $subject, ':now' => gmdate('Y-m-d H:i:s', $now)]
        );
        return $rows[0] ?? null;
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
        $bind = [
            ':subject' => $subject,
            ':scope' => $scope,
            ':reason' => $reason,
            ':rule' => $rule,
            ':evidence' => (string) json_encode($evidence),
            ':created' => gmdate('Y-m-d H:i:s', $now),
            ':expires' => gmdate('Y-m-d H:i:s', $expiresAt),
            ':by' => $createdBy,
        ];
        $sql = $this->sqlite
            ? 'INSERT INTO sg_blocks
                 (subject, scope, reason, rule, evidence, created_at, expires_at, created_by)
               VALUES (:subject, :scope, :reason, :rule, :evidence, :created, :expires, :by)
               ON CONFLICT(subject) DO UPDATE SET
                 scope = excluded.scope, reason = excluded.reason, rule = excluded.rule,
                 evidence = excluded.evidence, created_at = excluded.created_at,
                 expires_at = excluded.expires_at, created_by = excluded.created_by,
                 lifted_at = NULL'
            : 'INSERT INTO sg_blocks
                 (subject, scope, reason, rule, evidence, created_at, expires_at, created_by)
               VALUES (:subject, :scope, :reason, :rule, :evidence, :created, :expires, :by)
               ON DUPLICATE KEY UPDATE
                 scope = VALUES(scope), reason = VALUES(reason), rule = VALUES(rule),
                 evidence = VALUES(evidence), created_at = VALUES(created_at),
                 expires_at = VALUES(expires_at), created_by = VALUES(created_by),
                 lifted_at = NULL';
        $this->exec($sql, $bind);
        return (int) $this->scalar('SELECT id FROM sg_blocks WHERE subject = :s', [':s' => $subject]);
    }

    public function lift(string $subject, int $now): bool
    {
        $stmt = $this->pdo->prepare(
            'UPDATE sg_blocks SET lifted_at = :now
             WHERE subject = :s AND lifted_at IS NULL AND expires_at > :now'
        );
        $stmt->execute([':now' => gmdate('Y-m-d H:i:s', $now), ':s' => $subject]);
        return $stmt->rowCount() > 0;
    }

    public function prune(int $now, int $limit = 200): int
    {
        $limit = max(1, min(2000, $limit));
        $sql = $this->sqlite
            ? 'DELETE FROM sg_blocks WHERE id IN
                 (SELECT id FROM sg_blocks WHERE expires_at <= :cut LIMIT :limit)'
            : 'DELETE FROM sg_blocks WHERE expires_at <= :cut LIMIT :limit';
        $stmt = $this->pdo->prepare($sql);
        $stmt->bindValue(':cut', gmdate('Y-m-d H:i:s', $now - 86400));
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->rowCount();
    }

    public function listActive(int $now, int $limit = 100, int $offset = 0): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT * FROM sg_blocks WHERE lifted_at IS NULL AND expires_at > :now
             ORDER BY created_at DESC LIMIT :limit OFFSET :offset'
        );
        $stmt->bindValue(':now', gmdate('Y-m-d H:i:s', $now));
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
        $stmt->execute();
        return (array) $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function countActive(int $now): int
    {
        return (int) $this->scalar(
            'SELECT COUNT(*) FROM sg_blocks WHERE lifted_at IS NULL AND expires_at > :now',
            [':now' => gmdate('Y-m-d H:i:s', $now)]
        );
    }

    public function recentCount(string $subject, int $since): int
    {
        return (int) $this->scalar(
            'SELECT COUNT(*) FROM sg_blocks WHERE subject = :s AND created_at >= :since',
            [':s' => $subject, ':since' => gmdate('Y-m-d H:i:s', $since)]
        );
    }
}

final class PdoIncidents extends PdoBase implements Incidents
{
    public function record(
        string $subject,
        string $rule,
        string $severity,
        array $evidence,
        int $requestCount,
        int $blockId,
        int $now
    ): int {
        $this->exec(
            'INSERT INTO sg_incidents
                (ts, subject, rule, severity, evidence, request_count, block_id)
             VALUES (:ts, :subject, :rule, :severity, :evidence, :count, :block)',
            [
                ':ts' => gmdate('Y-m-d H:i:s', $now),
                ':subject' => $subject,
                ':rule' => $rule,
                ':severity' => $severity,
                ':evidence' => (string) json_encode($evidence),
                ':count' => $requestCount,
                ':block' => $blockId,
            ]
        );
        return (int) $this->pdo->lastInsertId();
    }

    public function recent(int $limit = 50, int $offset = 0): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT * FROM sg_incidents ORDER BY id DESC LIMIT :limit OFFSET :offset'
        );
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
        $stmt->execute();
        return (array) $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function countSince(int $since): int
    {
        return (int) $this->scalar(
            'SELECT COUNT(*) FROM sg_incidents WHERE ts >= :since',
            [':since' => gmdate('Y-m-d H:i:s', $since)]
        );
    }

    public function pruneBefore(int $before): int
    {
        $sql = $this->sqlite
            ? 'DELETE FROM sg_incidents WHERE id IN
                 (SELECT id FROM sg_incidents WHERE ts < :cut LIMIT 2000)'
            : 'DELETE FROM sg_incidents WHERE ts < :cut LIMIT 2000';
        $stmt = $this->pdo->prepare($sql);
        $stmt->execute([':cut' => gmdate('Y-m-d H:i:s', $before)]);
        return $stmt->rowCount();
    }
}
