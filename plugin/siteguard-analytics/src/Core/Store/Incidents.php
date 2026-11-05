<?php
declare(strict_types=1);

namespace SiteGuard\Core\Store;

/**
 * Security incidents. One row is written per escalation event, not per blocked
 * request, so a flood costs a handful of rows rather than thousands.
 */
interface Incidents
{
    /** @param array<string,mixed> $evidence */
    public function record(
        string $subject,
        string $rule,
        string $severity,
        array $evidence,
        int $requestCount,
        int $blockId,
        int $now
    ): int;

    /** @return list<array<string,mixed>> */
    public function recent(int $limit = 50, int $offset = 0): array;

    public function countSince(int $since): int;

    /** Incidents recorded for this subject since $since; drives the ladder. */
    public function countFor(string $subject, int $since): int;

    public function pruneBefore(int $before): int;
}
