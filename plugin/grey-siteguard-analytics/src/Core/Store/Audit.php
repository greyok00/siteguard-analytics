<?php
declare(strict_types=1);

namespace SiteGuard\Core\Store;





interface Audit
{
    
    public function record(int $actorId, string $action, string $target, array $details, int $now): int;

    
    public function recent(int $limit = 100, int $offset = 0): array;

    public function pruneBefore(int $before): int;
}
