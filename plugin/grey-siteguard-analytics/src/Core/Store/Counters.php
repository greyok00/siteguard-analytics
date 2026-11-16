<?php
declare(strict_types=1);

namespace SiteGuard\Core\Store;






interface Counters
{
    
    public function hit(string $key, int $ttlSeconds): int;

    
    public function get(string $key): int;

    
    public function prune(int $limit = 500): int;
}
