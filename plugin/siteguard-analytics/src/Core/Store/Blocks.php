<?php
declare(strict_types=1);

namespace SiteGuard\Core\Store;

/**
 * Temporary blocks. There is deliberately no "permanent" option: every row
 * carries an expiry, and expired rows are ignored on read and pruned later.
 */
interface Blocks
{
    /** @return array<string,mixed>|null the unexpired block for this subject */
    public function active(string $subject, int $now): ?array;

    /**
     * @param array<string,mixed> $evidence
     * @return int new block id, or 0 when an unexpired block already existed
     */
    public function add(
        string $subject,
        string $scope,
        string $reason,
        string $rule,
        array $evidence,
        int $now,
        int $expiresAt,
        string $createdBy = 'system'
    ): int;

    public function lift(string $subject, int $now): bool;

    public function prune(int $now, int $limit = 200): int;

    /** @return list<array<string,mixed>> */
    public function listActive(int $now, int $limit = 100, int $offset = 0): array;

    public function countActive(int $now): int;

    /**
     * Blocks created for this subject since $since. Fallback only: the ladder
     * counts incidents when an incident store is wired, because this table
     * keeps a single row per subject.
     */
    public function recentCount(string $subject, int $since): int;
}
