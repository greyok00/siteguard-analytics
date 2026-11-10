<?php
declare(strict_types=1);

namespace SiteGuard\Wp;

use SiteGuard\Core\Ip;

/**
 * Forward-confirmed reverse DNS for the crawlers whose traffic a site usually
 * wants. A user agent string alone proves nothing; the claimed bot is accepted
 * only when the address resolves to an operator hostname and that hostname
 * resolves back to the same address. Results are cached for 12 hours so the
 * lookup cost is paid once per address.
 */
final class Crawler
{
    /** Hostname suffixes, per operator, mapped to their required UA marker. */
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

        $ok = self::forwardConfirmed($ip);
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

    /** A cheap guess used only for display, never for a decision. */
    public static function looksAutomated(string $userAgent): bool
    {
        return (bool) preg_match('/bot|crawl|spider|scrape|headless|python-requests|curl|wget|go-http|java\//i', $userAgent);
    }
}
