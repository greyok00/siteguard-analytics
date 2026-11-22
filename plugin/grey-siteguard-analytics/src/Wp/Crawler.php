<?php
declare(strict_types=1);

namespace SiteGuard\Wp;

use SiteGuard\Core\Ip;








final class Crawler
{
    
    private const OPERATORS = [
        'googlebot.com' => 'googlebot',
        'google.com' => 'googlebot',
        'search.msn.com' => 'bingbot',
        'crawl.baidu.com' => 'baiduspider',
        'crawl.yandex.net' => 'yandex',
        'applebot.apple.com' => 'applebot',
        'duckduckgo.com' => 'duckduckbot',
    ];

    public static function verified(string $ip, string $userAgent): bool
    {
        if ($ip === '' || $userAgent === '') {
            return false;
        }
        $claimed = null;
        foreach (self::OPERATORS as $suffix => $marker) {
            if (stripos($userAgent, $marker) !== false) {
                $claimed = $marker;
                break;
            }
        }
        if ($claimed === null) {
            return false;
        }

        $key = 'sg_rdns_' . substr(hash_hmac('sha256', $ip, (string) get_option(Installer::SALT_OPTION, '')), 0, 32);
        $cached = get_transient($key);
        if (is_string($cached)) {
            return $cached === '1';
        }

        // The reverse lookup runs on a PHP worker inside the request and has
        // no timeout control. One worker resolves a fresh IP at a time; every
        // other request during the lookup fails fast and is not cached, so a
        // genuine crawler is verified on its next request instead.
        $lock = $key . '_lock';
        if (get_transient($lock)) {
            return false;
        }
        set_transient($lock, '1', 10);

        $ok = self::forwardConfirmed($ip);
        delete_transient($lock);
        set_transient($key, $ok ? '1' : '0', 12 * HOUR_IN_SECONDS);
        return $ok;
    }

    private static function forwardConfirmed(string $ip): bool
    {
        $host = @gethostbyaddr($ip);
        if (!is_string($host) || $host === '' || $host === $ip) {
            return false;
        }
        $host = strtolower(rtrim($host, '.'));
        $known = false;
        foreach (array_keys(self::OPERATORS) as $suffix) {
            if ($host === $suffix || str_ends_with($host, '.' . $suffix)) {
                $known = true;
                break;
            }
        }
        if (!$known) {
            return false;
        }
        $resolved = @gethostbynamel($host);
        if (!is_array($resolved)) {
            return false;
        }
        foreach ($resolved as $candidate) {
            if (Ip::normalize($candidate) === Ip::normalize($ip)) {
                return true;
            }
        }
        return false;
    }

    
    public static function looksAutomated(string $userAgent): bool
    {
        return (bool) preg_match('/bot|crawl|spider|scrape|headless|python-requests|curl|wget|go-http|java\//i', $userAgent);
    }
}
