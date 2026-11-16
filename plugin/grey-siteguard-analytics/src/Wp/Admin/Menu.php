<?php
declare(strict_types=1);

namespace SiteGuard\Wp\Admin;

use SiteGuard\Wp\Caps;







final class Menu
{
    public const OVERVIEW = 'siteguard';

    
    private const NOTICE_ACTION = 'siteguard_notice';

    
    public const VISITORS = 'visitors';
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
        
        
        wp_enqueue_script(
            'siteguard-admin',
            SITEGUARD_URL . 'assets/admin.js',
            [],
            SITEGUARD_VERSION,
            ['in_footer' => true]
        );
    }

    
    public static function url(string $anchor = ''): string
    {
        $url = admin_url('admin.php?page=' . self::OVERVIEW);
        return $anchor === '' || $anchor === self::OVERVIEW ? $url : $url . '#' . $anchor;
    }

    
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
