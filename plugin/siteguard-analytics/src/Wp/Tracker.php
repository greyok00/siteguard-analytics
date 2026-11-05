<?php
declare(strict_types=1);

namespace SiteGuard\Wp;

/**
 * Enqueues the first-party collector on front-end requests only. It is never
 * printed in feeds, REST responses, or the admin, and it collects nothing
 * beyond what the server already sees plus coarse screen and language hints.
 */
final class Tracker
{
    public static function boot(): void
    {
        add_action('wp_enqueue_scripts', [self::class, 'enqueue'], 20);
    }

    public static function enqueue(): void
    {
        if (is_admin() || is_feed() || is_robots() || is_trackback()) {
            return;
        }
        $settings = Config::settings();
        if (empty($settings['collect'])) {
            return;
        }
        $consent = (string) ($settings['consent_mode'] ?? 'none');

        wp_enqueue_script(
            'siteguard-tracker',
            SITEGUARD_URL . 'assets/tracker.js',
            [],
            SITEGUARD_VERSION,
            [
                'strategy' => 'defer',
                'in_footer' => true,
            ]
        );

        wp_add_inline_script(
            'siteguard-tracker',
            'window.SiteGuardConfig=' . wp_json_encode([
                'endpoint' => esc_url_raw(rest_url('siteguard/v1/collect')),
                'consent' => $consent,
                'sample' => 100,
            ]) . ';',
            'before'
        );
    }
}
