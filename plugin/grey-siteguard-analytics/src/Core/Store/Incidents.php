<?php
declare(strict_types=1);

namespace SiteGuard\Core\Store;





interface Incidents
{
    
    public function record(
        string $subject,
        string $rule,
        string $severity,
        array $evidence,
        int $requestCount,
        int $blockId,
        int $now
    ): int;

    
    public function recent(int $limit = 50, int $offset = 0): array;

    public function countSince(int $since): int;

    
    public function countFor(string $subject, int $since): int;

    public function pruneBefore(int $before): int;
}
