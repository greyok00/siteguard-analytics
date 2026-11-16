<?php
declare(strict_types=1);

namespace SiteGuard\Core\Store;






interface People
{
    




    public function touchSession(string $sessionId, array $meta, int $now, bool $newPageview): void;

    public function closeSession(string $sessionId, string $exitPath, int $now): void;

    


    public function touchVisitor(string $visitorId, int $now, bool $newSession, bool $newPageview, array $meta = []): void;

    public function linkIdentity(string $visitorId, int $accountId, int $now): void;

    public function countSessions(int $since, int $until): int;

    public function pruneBefore(int $before): int;
}
