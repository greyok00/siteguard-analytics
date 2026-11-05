<?php
declare(strict_types=1);

namespace SiteGuard\Core\Store;

/**
 * Bounded set membership per subject and window, used to spot breadth scans
 * ("hit 150 different paths in ten minutes"). Only a short non-reversible path
 * hash is stored, never the URL.
 */
interface Distinct
{
    /** Adds a path hash; returns true when it was new for this window. */
    public function touch(string $subject, string $pathHash, int $windowStart): bool;

    /** Number of distinct paths seen at or after $since. */
    public function count(string $subject, int $since): int;

    public function prune(int $olderThan): int;
}
