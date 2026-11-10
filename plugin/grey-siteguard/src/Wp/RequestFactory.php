<?php
declare(strict_types=1);

namespace SiteGuard\Wp;

use SiteGuard\Core\Classifier;
use SiteGuard\Core\Crypto;
use SiteGuard\Core\Ip;
use SiteGuard\Core\RequestContext;

/**
 * Builds the enforcement context from the current WordPress request.
 *
 * Only server-observable facts are trusted here. The visitor and session ids
 * come from first-party cookies and are used to attribute analytics rows and
 * to pick a counter; a forged value can only throttle the forger.
 */
final class RequestFactory
{
    /** @param array<string,mixed> $overrides */
    public static function build(array $overrides = []): RequestContext
    {
        $settings = Config::settings();
        $crypto = Config::crypto();

        $uri = sanitize_text_field(wp_unslash((string) ($_SERVER['REQUEST_URI'] ?? '/')));
        $path = (string) (wp_parse_url($uri, PHP_URL_PATH) ?: '/');
        $query = sanitize_text_field(wp_unslash((string) ($_SERVER['QUERY_STRING'] ?? '')));

        $headers = self::headers();
        $remote = sanitize_text_field(wp_unslash((string) ($_SERVER['REMOTE_ADDR'] ?? '')));
        $ip = Ip::client($remote, $headers, (string) ($settings['trusted_proxies'] ?? ''));
        $ipSubject = Ip::subject($ip);
        if ($ipSubject === 'ip:unknown') {
            $ipSubject = '';
        }

        $userAgent = self::userAgent();
        $uaHash = $userAgent === ''
            ? ''
            : substr($crypto->subject('ua', $userAgent), -32);

        $visitor = self::cookieId('sg_v');
        $session = self::cookieId('sg_s');

        $isAjax = function_exists('wp_doing_ajax') && wp_doing_ajax();
        $isCron = function_exists('wp_doing_cron') && wp_doing_cron();
        $isAdmin = function_exists('is_admin') && is_admin();

        $class = Classifier::classify([
            'path' => $path,
            'query' => $query,
            'method' => sanitize_text_field(wp_unslash((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'))),
            'is_rest' => defined('REST_REQUEST') && REST_REQUEST,
            'is_ajax' => $isAjax,
            'is_login' => false,
            'is_admin' => $isAdmin && !$isAjax,
            'is_cron' => $isCron,
        ]);

        $ctx = new RequestContext(
            method: strtoupper(sanitize_text_field(wp_unslash((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET')))),
            path: substr($path, 0, 255),
            query: substr($query, 0, 512),
            endpointClass: $class,
            ip: $ip,
            ipSubject: $ipSubject,
            userAgent: $userAgent,
            userAgentHash: $uaHash,
            fingerprint: '',
            visitorId: $visitor,
            sessionId: $session,
            accountId: self::accountId(),
            isAuthenticated: function_exists('is_user_logged_in') && is_user_logged_in(),
            verifiedCrawler: $ip !== '' && Crawler::verified($ip, $userAgent),
            isBotLikely: Crawler::looksAutomated($userAgent)
        );

        return $overrides ? self::with($ctx, $overrides) : $ctx;
    }

    /** @param array<string,mixed> $overrides */
    private static function with(RequestContext $ctx, array $overrides): RequestContext
    {
        return new RequestContext(
            method: (string) ($overrides['method'] ?? $ctx->method),
            path: (string) ($overrides['path'] ?? $ctx->path),
            query: (string) ($overrides['query'] ?? $ctx->query),
            endpointClass: (string) ($overrides['endpointClass'] ?? $ctx->endpointClass),
            ip: (string) ($overrides['ip'] ?? $ctx->ip),
            ipSubject: (string) ($overrides['ipSubject'] ?? $ctx->ipSubject),
            userAgent: (string) ($overrides['userAgent'] ?? $ctx->userAgent),
            userAgentHash: (string) ($overrides['userAgentHash'] ?? $ctx->userAgentHash),
            fingerprint: (string) ($overrides['fingerprint'] ?? $ctx->fingerprint),
            visitorId: (string) ($overrides['visitorId'] ?? $ctx->visitorId),
            sessionId: (string) ($overrides['sessionId'] ?? $ctx->sessionId),
            accountId: array_key_exists('accountId', $overrides) ? $overrides['accountId'] : $ctx->accountId,
            isAuthenticated: (bool) ($overrides['isAuthenticated'] ?? $ctx->isAuthenticated),
            verifiedCrawler: (bool) ($overrides['verifiedCrawler'] ?? $ctx->verifiedCrawler),
            isBotLikely: (bool) ($overrides['isBotLikely'] ?? $ctx->isBotLikely)
        );
    }

    private static function accountId(): ?int
    {
        if (!function_exists('get_current_user_id')) {
            return null;
        }
        $id = (int) get_current_user_id();
        return $id > 0 ? $id : null;
    }

    /** @return array<string,string> */
    private static function headers(): array
    {
        $out = [];
        if (function_exists('getallheaders')) {
            foreach ((array) getallheaders() as $name => $value) {
                $out[(string) $name] = is_array($value) ? implode(',', $value) : (string) $value;
            }
        }
        foreach ($_SERVER as $key => $value) {
            if (str_starts_with((string) $key, 'HTTP_')) {
                $name = str_replace('_', '-', substr((string) $key, 5));
                if (!isset($out[$name])) {
                    $out[$name] = (string) $value;
                }
            }
        }
        return $out;
    }

    private static function userAgent(): string
    {
        $ua = sanitize_text_field(wp_unslash((string) ($_SERVER['HTTP_USER_AGENT'] ?? '')));
        // Control characters never belong in a stored value; length is capped
        // so a megabyte of header cannot be written into the database.
        $ua = preg_replace('/[\x00-\x1F\x7F]/', '', $ua) ?? '';
        return substr($ua, 0, 512);
    }

    private static function cookieId(string $name): string
    {
        $value = sanitize_text_field(wp_unslash((string) ($_COOKIE[$name] ?? '')));
        return Crypto::isId($value) ? $value : '';
    }
}
