<?php
declare(strict_types=1);

namespace SiteGuard\Core\Store;

/**
 * Append-only analytics and security rows. Browser-sourced rows carry
 * source='browser' and are untrusted; the dashboard separates them from
 * source='server' rows so a forged beacon cannot inflate the numbers.
 */
interface Events
{
    /**
     * @param array<string,mixed> $row
     * @return int inserted id, or 0 when the dedupe key already existed
     */
    public function insert(array $row): int;

    /** @return list<array<string,mixed>> */
    public function recent(int $limit = 50, string $source = ''): array;

    /** Total rows created at or after $since, optionally filtered by source. */
    public function countSince(int $since, string $source = ''): int;

    public function pruneBefore(int $before): int;
}
