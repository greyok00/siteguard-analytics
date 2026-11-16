<?php
declare(strict_types=1);

namespace SiteGuard\Core\Store;






interface Distinct
{
    
    public function touch(string $subject, string $pathHash, int $windowStart): bool;

    
    public function count(string $subject, int $since): int;

    public function prune(int $olderThan): int;
}
