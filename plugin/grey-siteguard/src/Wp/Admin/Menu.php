<?php
declare(strict_types=1);

namespace SiteGuard\Wp\Admin;

use SiteGuard\Wp\Caps;

/**
 * Admin menu. Everything the plugin does lives on one page; the constants
 * below are section anchors on that page, not separate screens. Each section
 * checks its own capability again before rendering — the menu is not the
 * security boundary, and neither is the header navigation.
 */
final class Menu
{
    public const OVERVIEW = 'siteguard';

    /** Guards the one-time notice carried in the redirect URL. */
    private const NOTICE_ACTION = 'siteguard_notice';

    /** Section anchors on the single page. */
    public const VISITORS = 'visitors';
    public const PROFILES = 'profiles';
    public const SECURITY = 'security';
    public const OPERATIONS = 'operations';
    public const SETTINGS = 'settings';

    public static function boot(): void
    {
        add_action('admin_menu', [self::class, 'register']);
        add_action('admin_enqueue_scripts', [self::class, 'assets']);
        Actions::boot();
    }

    public static function register(): void
    {
        add_menu_page(
            'SiteGuard',
            'SiteGuard',
            Caps::VIEW_ANALYTICS,
            self::OVERVIEW,
            [Page::class, 'render'],
            'dashicons-shield',
            58
        );
    }

    public static function assets(string $hook): void
    {
        if (!str_contains($hook, 'siteguard')) {
            return;
        }
        wp_enqueue_style(
            'siteguard-admin',
            SITEGUARD_URL . 'assets/admin.css',
            [],
            SITEGUARD_VERSION
        );
        // Optional: without it all sections stay visible and the strip links
        // to each one. With it the strip behaves as tabs.
        wp_enqueue_script(
            'siteguard-admin',
            SITEGUARD_URL . 'assets/admin.js',
            [],
            SITEGUARD_VERSION,
            ['in_footer' => true]
        );
    }

    /** The single page, optionally scrolled to one of its sections. */
    public static function url(string $anchor = ''): string
    {
        $url = admin_url('admin.php?page=' . self::OVERVIEW);
        return $anchor === '' || $anchor === self::OVERVIEW ? $url : $url . '#' . $anchor;
    }

    /** Redirects to the single page with a one-time notice. */
    public static function redirect(string $anchor, string $notice, string $type = 'success'): void
    {
        $url = add_query_arg(
            [
                'page' => self::OVERVIEW,
                'sg_notice' => rawurlencode($notice),
                'sg_type' => $type,
                '_wpnonce' => wp_create_nonce(self::NOTICE_ACTION),
            ],
            admin_url('admin.php')
        );
        if ($anchor !== '' && $anchor !== self::OVERVIEW) {
            $url .= '#' . rawurlencode($anchor);
        }
        wp_safe_redirect($url);
        exit;
    }

    public static function maybeNotice(): void
    {
        if (!isset($_GET['sg_notice'], $_GET['_wpnonce'])) {
            return;
        }
        $nonce = sanitize_text_field(wp_unslash((string) $_GET['_wpnonce']));
        if (!wp_verify_nonce($nonce, self::NOTICE_ACTION)) {
            return;
        }
        $message = sanitize_text_field(wp_unslash((string) $_GET['sg_notice']));
        $type = isset($_GET['sg_type'])
            ? sanitize_key(wp_unslash((string) $_GET['sg_type']))
            : 'success';
        if (!in_array($type, ['success', 'warning', 'error', 'info'], true)) {
            $type = 'success';
        }
        Views::notice($message, $type);
    }
}
