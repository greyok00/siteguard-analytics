<?php
declare(strict_types=1);

namespace SiteGuard\Core\Store;

/**
 * Sessions, visitors, and the visitor↔account correlation table. The
 * correlation is additive: a browser seen under two accounts produces two
 * rows, never a merged identity.
 */
interface People
{
    /**
     * Creates a session on first beacon and updates it afterwards.
     *
     * @param array{visitor?:string,account_id?:int,landing?:string,device?:string,browser?:string,ip?:string,ua?:string,ip_hash?:string} $meta
     */
    public function touchSession(string $sessionId, array $meta, int $now, bool $newPageview): void;

    public function closeSession(string $sessionId, string $exitPath, int $now): void;

    /**
     * @param array{ip?:string,ua?:string,profile?:?string,last_path?:string} $meta
     */
    public function touchVisitor(string $visitorId, int $now, bool $newSession, bool $newPageview, array $meta = []): void;

    public function linkIdentity(string $visitorId, int $accountId, int $now): void;

    /**
     * The browser-reported signals last stored for a visitor, decoded.
     * An unknown or malformed row answers [] (silence is clean, not a lie);
     * the WAF consults this to score stored device-lie evidence.
     * @return array<string,mixed>
     */
    public function profileFor(string $visitorId): array;

    public function countSessions(int $since, int $until): int;

    public function pruneBefore(int $before): int;
}
