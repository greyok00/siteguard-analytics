<?php
declare(strict_types=1);

namespace SiteGuard\Core;

/**
 * Counter and block subject strings. The prefix makes the tables readable and
 * prevents an account id and an IP prefix from ever colliding.
 */
final class Subjects
{
    public const ACCOUNT_PREFIX = 'a:';
    public const VISITOR_PREFIX = 'v:';
    public const IP_PREFIX = 'ip';

    public static function account(int $accountId): string
    {
        return self::ACCOUNT_PREFIX . max(0, $accountId);
    }

    public static function visitor(string $visitorId): string
    {
        return self::VISITOR_PREFIX . substr($visitorId, 0, 32);
    }

    /** @param string $ipSubject a value produced by Ip::subject() */
    public static function ip(string $ipSubject): string
    {
        return substr($ipSubject, 0, 48);
    }

    /**
     * The window length is part of the key. Without it the 10s and 60s
     * windows share a key whenever a request lands in the first second of a
     * minute, doubling the burst count and denying well below the limit.
     */
    public static function counterKey(string $class, string $subject, int $window, int $windowStart): string
    {
        return $class . '|' . $subject . '|w' . $window . '|' . $windowStart;
    }
}
