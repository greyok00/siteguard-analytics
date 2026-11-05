<?php
declare(strict_types=1);

namespace SiteGuard\Core\Store;

/**
 * Privileged-action log. Every settings change, block, unblock, export, and
 * protection toggle is written here with the acting account.
 */
interface Audit
{
    /** @param array<string,mixed> $details */
    public function record(int $actorId, string $action, string $target, array $details, int $now): int;

    /** @return list<array<string,mixed>> */
    public function recent(int $limit = 100, int $offset = 0): array;

    public function pruneBefore(int $before): int;
}
