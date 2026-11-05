<?php
declare(strict_types=1);

namespace SiteGuard\Wp;

use SiteGuard\Core\Classifier;
use SiteGuard\Core\Decision;

/**
 * WordPress enforcement points.
 *
 * parse_request is the earliest hook that runs after WordPress has decided
 * what the request is but before the main query executes, so a flood is
 * stopped before the expensive work. REST, admin-ajax, and wp-login.php each
 * have their own entry points and are denied in their own way so the client
 * receives the correct status and content type.
 *
 * Nothing is enforced for administrators: an owner must always be able to
 * reach wp-admin and recover from a bad rule.
 */
final class Guard
{
    public static function boot(): void
    {
        add_action('parse_request', [self::class, 'onParseRequest'], 1);
        add_action('init', [self::class, 'onAjax'], 1);
        add_action('login_init', [self::class, 'onLogin'], 1);
        add_filter('rest_pre_dispatch', [self::class, 'onRest'], 10, 3);
    }

    public static function onParseRequest($wp = null): void
    {
        if (!self::active()) {
            return;
        }
        if (self::isRestRequest()) {
            return; // handled in rest_pre_dispatch
        }
        if (is_admin()) {
            return; // wp-admin is never rate limited
        }
        $ctx = RequestFactory::build();
        self::apply($ctx, 'front');
    }

    public static function onAjax(): void
    {
        if (!self::active() || !function_exists('wp_doing_ajax') || !wp_doing_ajax()) {
            return;
        }
        $ctx = RequestFactory::build();
        self::apply($ctx, 'ajax');
    }

    public static function onLogin(): void
    {
        if (!self::active()) {
            return;
        }
        $ctx = RequestFactory::build();
        self::apply($ctx, 'login');
    }

    /**
     * @param mixed $result
     * @param mixed $server
     * @param mixed $request
     * @return mixed
     */
    public static function onRest($result, $server, $request)
    {
        if ($result !== null || !self::active()) {
            return $result;
        }
        $route = is_object($request) && method_exists($request, 'get_route')
            ? (string) $request->get_route()
            : '';
        $ctx = RequestFactory::build([
            'path' => '/wp-json' . $route,
            'endpointClass' => Classifier::REST,
        ]);
        $decision = self::decide($ctx);
        if ($decision === null || !$decision->denied()) {
            return $result;
        }
        return new \WP_Error(
            'siteguard_limited',
            self::message($decision),
            [
                'status' => $decision->status,
                'headers' => ['Retry-After' => (string) $decision->retryAfter],
                'siteguard' => ['rule' => $decision->rule, 'scope' => $decision->scope],
            ]
        );
    }

    /**
     * parse_request runs at priority 1, before WordPress defines REST_REQUEST
     * (rest_api_loaded runs at priority 10), so the constant cannot be relied
     * on here. Without this check a REST flood was denied with the HTML error
     * page instead of the JSON error the REST client expects.
     */
    private static function isRestRequest(): bool
    {
        if (defined('REST_REQUEST') && REST_REQUEST) {
            return true;
        }
        $uri = sanitize_text_field(wp_unslash((string) ($_SERVER['REQUEST_URI'] ?? '')));
        $query = (string) wp_parse_url($uri, PHP_URL_QUERY);
        if ($query !== '') {
            // Sites without pretty permalinks pass the route as index.php?rest_route=.
            parse_str($query, $params);
            if (isset($params['rest_route'])) {
                return true;
            }
        }
        $path = (string) wp_parse_url($uri, PHP_URL_PATH);
        $prefix = rtrim((string) wp_parse_url((string) rest_url(), PHP_URL_PATH), '/');
        return $prefix !== '' && ($path === $prefix || str_starts_with($path, $prefix . '/'));
    }

    private static function active(): bool
    {
        if (defined('WP_CLI') && WP_CLI) {
            return false;
        }
        if (Config::emergencyOff()) {
            return false;
        }
        if (!Installer::ready()) {
            return false;
        }
        if (function_exists('current_user_can') && current_user_can('manage_options')) {
            return false;
        }
        return true;
    }

    private static function apply(\SiteGuard\Core\RequestContext $ctx, string $surface): void
    {
        $decision = self::decide($ctx);
        if ($decision === null || !$decision->denied()) {
            return;
        }

        if ($surface === 'front') {
            self::denyFront($decision);
            return;
        }
        if ($surface === 'login' || $surface === 'ajax') {
            self::denyPlain($decision);
        }
    }

    private static function decide(\SiteGuard\Core\RequestContext $ctx): ?Decision
    {
        try {
            return Config::enforcer()->check($ctx);
        } catch (\Throwable $e) {
            // Fail open: a storage fault must not take the site down. The
            // failure is kept for the diagnostics screen.
            update_option('siteguard_last_error', [
                'at' => time(),
                'message' => substr($e->getMessage(), 0, 300),
            ], false);
            return null;
        }
    }

    private static function denyFront(Decision $decision): void
    {
        nocache_headers();
        status_header($decision->status);
        header('Retry-After: ' . $decision->retryAfter);
        header('X-SiteGuard: blocked');
        wp_die(
            esc_html(self::message($decision)),
            esc_html__('Too Many Requests', 'grey-siteguard-analytics'),
            [
                'response' => absint($decision->status),
                'back_link' => false,
            ]
        );
    }

    private static function denyPlain(Decision $decision): void
    {
        nocache_headers();
        status_header($decision->status);
        header('Retry-After: ' . $decision->retryAfter);
        header('X-SiteGuard: blocked');
        header('Content-Type: text/plain; charset=utf-8');
        echo esc_html(self::message($decision));
        exit;
    }

    private static function message(Decision $decision): string
    {
        $seconds = max(1, $decision->retryAfter);
        $minutes = (int) ceil($seconds / 60);
        if ($seconds < 120) {
            return sprintf(
                'Too many requests. Please wait %d seconds and try again.',
                $seconds
            );
        }
        return sprintf(
            'Too many requests. Please wait about %d minutes and try again.',
            $minutes
        );
    }
}
