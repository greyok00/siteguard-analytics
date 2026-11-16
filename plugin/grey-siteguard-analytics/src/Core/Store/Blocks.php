<?php
declare(strict_types=1);

namespace SiteGuard\Core\Store;





interface Blocks
{
    
    public function active(string $subject, int $now): ?array;

    



    public function add(
        string $subject,
        string $scope,
        string $reason,
        string $rule,
        array $evidence,
        int $now,
        int $expiresAt,
        string $createdBy = 'system'
    ): int;

    public function lift(string $subject, int $now): bool;

    public function prune(int $now, int $limit = 200): int;

    
    public function listActive(int $now, int $limit = 100, int $offset = 0): array;

    public function countActive(int $now): int;

    




    public function recentCount(string $subject, int $since): int;
}
