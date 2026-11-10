<?php
declare(strict_types=1);

namespace SiteGuard\Core\Store;

/**
 * Atomic fixed-window counters. Implementations MUST increment atomically in
 * one statement; a read-modify-write loop would undercount under concurrency
 * and let a parallel request slip through.
 */
interface Counters
{
    /** Increments and returns the new count. */
    public function hit(string $key, int $ttlSeconds): int;

    /** Current count without incrementing; 0 when absent or expired. */
    public function get(string $key): int;

    /** Removes expired rows; returns how many. */
    public function prune(int $limit = 500): int;
}
