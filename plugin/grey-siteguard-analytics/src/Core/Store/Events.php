<?php
declare(strict_types=1);

namespace SiteGuard\Core\Store;






interface Events
{
    



    public function insert(array $row): int;

    
    public function recent(int $limit = 50, string $source = ''): array;

    
    public function countSince(int $since, string $source = ''): int;

    public function pruneBefore(int $before): int;
}
