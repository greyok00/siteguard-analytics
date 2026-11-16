<?php
declare(strict_types=1);

namespace SiteGuard\Core;





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

    
    public static function ip(string $ipSubject): string
    {
        return substr($ipSubject, 0, 48);
    }

    




    public static function counterKey(string $class, string $subject, int $window, int $windowStart): string
    {
        return $class . '|' . $subject . '|w' . $window . '|' . $windowStart;
    }
}
