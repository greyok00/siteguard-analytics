<?php
declare(strict_types=1);

namespace SiteGuard\Core;

/**
 * Maps a request onto one endpoint class. Classes exist because a feed, a REST
 * call, and a product page have different legitimate rates; one blanket limit
 * would either break checkout or leave the feed open.
 *
 * Input is intentionally WordPress-shaped but the function is pure, so the
 * Slim adapter classifies with the same rules.
 */
final class Classifier
{
    public const HTML = 'html';
    public const SEARCH = 'search';
    public const FEED = 'feed';
    public const REST = 'rest';
    public const AJAX = 'ajax';
    public const API = 'api';
    public const LOGIN = 'login';
    public const CART = 'cart';
    public const CHECKOUT = 'checkout';
    public const DOWNLOAD = 'download';
    /** Admin screens and cron are inventoried but not enforced by default. */
    public const ADMIN = 'admin';
    public const UNMANAGED = 'unmanaged';

    /** Classes the enforcer may deny. */
    public const MANAGED = [
        self::HTML, self::SEARCH, self::FEED, self::REST, self::AJAX,
        self::API, self::LOGIN, self::CART, self::CHECKOUT, self::DOWNLOAD,
    ];

    /**
     * @param array{
     *   path?: string, query?: string, method?: string,
     *   is_rest?: bool, is_ajax?: bool, is_feed?: bool, is_search?: bool,
     *   is_login?: bool, is_admin?: bool, is_cron?: bool, is_download?: bool,
     *   is_cart?: bool, is_checkout?: bool
     * } $signals
     */
    public static function classify(array $signals): string
    {
        $path = (string) ($signals['path'] ?? '/');
        $method = strtoupper((string) ($signals['method'] ?? 'GET'));
        $query = (string) ($signals['query'] ?? '');

        if (!empty($signals['is_cron'])) {
            return self::UNMANAGED;
        }
        if (!empty($signals['is_login'])
            || preg_match('#/wp-login\.php$#i', $path)
            || self::pathMatches($path, ['login', 'signin', 'sign-in'])
        ) {
            return self::LOGIN;
        }
        // admin-ajax.php lives under /wp-admin but is front-end traffic, so it
        // is classified before the admin exclusion.
        if (!empty($signals['is_ajax']) || preg_match('#/wp-admin/admin-ajax\.php$#i', $path)) {
            return self::AJAX;
        }
        if (!empty($signals['is_admin']) || preg_match('#^/wp-admin(/|$)#i', $path)) {
            // wp-admin is excluded from enforcement: a rule mistake there can
            // lock the owner out of recovery. The login form is still covered.
            return self::ADMIN;
        }
        if (!empty($signals['is_rest']) || preg_match('#^/wp-json(/|$)#i', $path)) {
            return self::REST;
        }
        if (!empty($signals['is_checkout']) || self::pathMatches($path, ['checkout', 'order-pay', 'order-received'])) {
            return self::CHECKOUT;
        }
        if (!empty($signals['is_cart']) || self::pathMatches($path, ['cart', 'basket'])) {
            return self::CART;
        }
        if (!empty($signals['is_download']) || self::queryHas($query, 'download_file')
            || preg_match('#/download(/|$)|\.(zip|pdf|epub|tar\.gz)$#i', $path)) {
            return self::DOWNLOAD;
        }
        if (!empty($signals['is_feed']) || preg_match('#/feed/?$|/rss/?$#i', $path) || self::queryHas($query, 'feed')) {
            return self::FEED;
        }
        if (!empty($signals['is_search']) || self::queryHas($query, 's')
            || preg_match('#(^|/)(search|find)(/|$)#i', $path)) {
            return self::SEARCH;
        }
        if (self::queryHas($query, 'wc-ajax') || str_contains($path, '/wp-json/wc/')) {
            return self::API;
        }
        if ($method === 'POST' && self::queryHas($query, 'rest_route')) {
            return self::API;
        }
        return self::HTML;
    }

    private static function pathMatches(string $path, array $segments): bool
    {
        foreach ($segments as $segment) {
            if (preg_match('#(^|/)' . preg_quote($segment, '#') . '(/|$)#i', $path)) {
                return true;
            }
        }
        return false;
    }

    private static function queryHas(string $query, string $key): bool
    {
        if ($query === '') {
            return false;
        }
        parse_str($query, $parsed);
        return array_key_exists($key, $parsed);
    }
}
