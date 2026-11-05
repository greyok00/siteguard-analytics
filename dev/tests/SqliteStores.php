<?php
declare(strict_types=1);

namespace SiteGuard\Tests;

use PDO;
use SiteGuard\Core\Store\Blocks;
use SiteGuard\Core\Store\Counters;
use SiteGuard\Core\Store\Distinct;
use SiteGuard\Core\Store\Incidents;

/**
 * SQLite implementations used only by the test suite. They mirror the SQL
 * semantics of the wpdb stores (atomic upsert, expired-key reset, single row
 * per block subject) so the tests exercise the real enforcer logic.
 */
final class SqliteDb
{
    public PDO $pdo;

    public function __construct()
    {
        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->pdo->exec('CREATE TABLE counters (k TEXT PRIMARY KEY, n INTEGER NOT NULL, expires_at INTEGER NOT NULL)');
        $this->pdo->exec('CREATE TABLE distinct_paths (
            subject TEXT NOT NULL, path_hash TEXT NOT NULL, window_start INTEGER NOT NULL,
            PRIMARY KEY (subject, path_hash, window_start))');
        $this->pdo->exec('CREATE TABLE blocks (
            id INTEGER PRIMARY KEY AUTOINCREMENT, subject TEXT NOT NULL UNIQUE,
            scope TEXT NOT NULL, reason TEXT NOT NULL, rule TEXT NOT NULL, evidence TEXT,
            created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
            created_by TEXT NOT NULL, lifted_at INTEGER)');
        $this->pdo->exec('CREATE TABLE incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, subject TEXT NOT NULL,
            rule TEXT NOT NULL, severity TEXT NOT NULL, evidence TEXT,
            request_count INTEGER NOT NULL, block_id INTEGER NOT NULL)');
    }
}

final class SqliteCounters implements Counters
{
    private \SiteGuard\Core\Clock $clock;

    public function __construct(private PDO $pdo, ?\SiteGuard\Core\Clock $clock = null)
    {
        $this->clock = $clock ?? new \SiteGuard\Core\SystemClock();
    }

    public function hit(string $key, int $ttlSeconds): int
    {
        $now = $this->clock->now();
        $expires = $now + max(1, $ttlSeconds);
        $stmt = $this->pdo->prepare(
            'INSERT INTO counters (k, n, expires_at) VALUES (:k, 1, :exp)
             ON CONFLICT(k) DO UPDATE SET
               n = CASE WHEN expires_at <= :now THEN 1 ELSE n + 1 END,
               expires_at = :exp'
        );
        $stmt->execute([':k' => $key, ':exp' => $expires, ':now' => $now]);
        $read = $this->pdo->prepare('SELECT n FROM counters WHERE k = :k AND expires_at > :now');
        $read->execute([':k' => $key, ':now' => $now]);
        return (int) $read->fetchColumn();
    }

    public function get(string $key): int
    {
        $stmt = $this->pdo->prepare('SELECT n FROM counters WHERE k = :k AND expires_at > :now');
        $stmt->execute([':k' => $key, ':now' => $this->clock->now()]);
        return (int) $stmt->fetchColumn();
    }

    public function prune(int $limit = 500): int
    {
        $stmt = $this->pdo->prepare(
            'DELETE FROM counters WHERE k IN (SELECT k FROM counters WHERE expires_at <= :now LIMIT :limit)'
        );
        $stmt->bindValue(':now', $this->clock->now());
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->rowCount();
    }
}

final class SqliteDistinct implements Distinct
{
    public function __construct(private PDO $pdo)
    {
    }

    public function touch(string $subject, string $pathHash, int $windowStart): bool
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO distinct_paths (subject, path_hash, window_start) VALUES (:s, :p, :w)
             ON CONFLICT DO NOTHING'
        );
        $stmt->execute([':s' => $subject, ':p' => $pathHash, ':w' => $windowStart]);
        return $stmt->rowCount() > 0;
    }

    public function count(string $subject, int $since): int
    {
        $stmt = $this->pdo->prepare(
            'SELECT COUNT(*) FROM distinct_paths WHERE subject = :s AND window_start >= :w'
        );
        $stmt->execute([':s' => $subject, ':w' => $since]);
        return (int) $stmt->fetchColumn();
    }

    public function prune(int $olderThan): int
    {
        $stmt = $this->pdo->prepare('DELETE FROM distinct_paths WHERE window_start < :w');
        $stmt->execute([':w' => $olderThan]);
        return $stmt->rowCount();
    }
}

final class SqliteBlocks implements Blocks
{
    public function __construct(private PDO $pdo)
    {
    }

    public function active(string $subject, int $now): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT * FROM blocks WHERE subject = :s AND lifted_at IS NULL AND expires_at > :now
             ORDER BY id DESC LIMIT 1'
        );
        $stmt->execute([':s' => $subject, ':now' => $now]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
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
        $stmt = $this->pdo->prepare(
            'INSERT INTO blocks (subject, scope, reason, rule, evidence, created_at, expires_at, created_by)
             VALUES (:s, :scope, :reason, :rule, :ev, :created, :expires, :by)
             ON CONFLICT(subject) DO UPDATE SET
               scope = excluded.scope, reason = excluded.reason, rule = excluded.rule,
               evidence = excluded.evidence, created_at = excluded.created_at,
               expires_at = excluded.expires_at, created_by = excluded.created_by, lifted_at = NULL'
        );
        $stmt->execute([
            ':s' => $subject,
            ':scope' => $scope,
            ':reason' => $reason,
            ':rule' => $rule,
            ':ev' => json_encode($evidence),
            ':created' => $now,
            ':expires' => $expiresAt,
            ':by' => $createdBy,
        ]);
        $id = $this->pdo->prepare('SELECT id FROM blocks WHERE subject = :s');
        $id->execute([':s' => $subject]);
        return (int) $id->fetchColumn();
    }

    public function lift(string $subject, int $now): bool
    {
        $stmt = $this->pdo->prepare(
            'UPDATE blocks SET lifted_at = :now WHERE subject = :s AND lifted_at IS NULL AND expires_at > :now'
        );
        $stmt->execute([':now' => $now, ':s' => $subject]);
        return $stmt->rowCount() > 0;
    }

    public function prune(int $now, int $limit = 200): int
    {
        $stmt = $this->pdo->prepare(
            'DELETE FROM blocks WHERE id IN (SELECT id FROM blocks WHERE expires_at <= :cut LIMIT :limit)'
        );
        $stmt->bindValue(':cut', $now - 86400);
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->execute();
        return $stmt->rowCount();
    }

    public function listActive(int $now, int $limit = 100, int $offset = 0): array
    {
        $stmt = $this->pdo->prepare(
            'SELECT * FROM blocks WHERE lifted_at IS NULL AND expires_at > :now
             ORDER BY created_at DESC LIMIT :limit OFFSET :offset'
        );
        $stmt->bindValue(':now', $now);
        $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
        $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
        $stmt->execute();
        return (array) $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function countActive(int $now): int
    {
        $stmt = $this->pdo->prepare(
            'SELECT COUNT(*) FROM blocks WHERE lifted_at IS NULL AND expires_at > :now'
        );
        $stmt->execute([':now' => $now]);
        return (int) $stmt->fetchColumn();
    }

    public function recentCount(string $subject, int $since): int
    {
        $stmt = $this->pdo->prepare(
            'SELECT COUNT(*) FROM blocks WHERE subject = :s AND created_at >= :since'
        );
        $stmt->execute([':s' => $subject, ':since' => $since]);
        return (int) $stmt->fetchColumn();
    }
}

final class SqliteIncidents implements Incidents
{
    /** @var list<array<string,mixed>> */
    public array $rows = [];

    public function __construct(private PDO $pdo)
    {
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
        $stmt = $this->pdo->prepare(
            'INSERT INTO incidents (ts, subject, rule, severity, evidence, request_count, block_id)
             VALUES (:ts, :s, :rule, :sev, :ev, :count, :block)'
        );
        $stmt->execute([
            ':ts' => $now,
            ':s' => $subject,
            ':rule' => $rule,
            ':sev' => $severity,
            ':ev' => json_encode($evidence),
            ':count' => $requestCount,
            ':block' => $blockId,
        ]);
        $this->rows[] = ['subject' => $subject, 'rule' => $rule, 'severity' => $severity];
        return (int) $this->pdo->lastInsertId();
    }

    public function recent(int $limit = 50, int $offset = 0): array
    {
        return array_slice(array_reverse($this->rows), $offset, $limit);
    }

    public function countSince(int $since): int
    {
        return count($this->rows);
    }

    public function countFor(string $subject, int $since): int
    {
        $stmt = $this->pdo->prepare(
            'SELECT COUNT(*) FROM incidents WHERE subject = :s AND ts >= :since'
        );
        $stmt->execute([':s' => $subject, ':since' => $since]);
        return (int) $stmt->fetchColumn();
    }

    public function pruneBefore(int $before): int
    {
        return 0;
    }
}

/** A clock the test can move. */
final class FakeClock implements \SiteGuard\Core\Clock
{
    public function __construct(private int $now)
    {
    }

    public function now(): int
    {
        return $this->now;
    }

    public function set(int $now): void
    {
        $this->now = $now;
    }

    public function advance(int $seconds): void
    {
        $this->now += $seconds;
    }
}
