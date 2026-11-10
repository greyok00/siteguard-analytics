<?php
/**
 * Plugin Name: Grey SiteGuard + Analytics
 * Plugin URI:  https://randybarham.com
 * Description: Active request protection, incident records, and light first-party analytics for WordPress.
 * Version:     0.1.9
 * Requires at least: 6.4
 * Requires PHP: 8.1
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: grey-siteguard-analytics
 *
 * SiteGuard decides before a protected response is produced: deterministic
 * rate limits and temporary blocks run from `parse_request` (before the main
 * query), REST decisions from `rest_pre_dispatch`, and login attempts from
 * `login_init`. Analytics is best effort and never decides access.
 */

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}

define('SITEGUARD_VERSION', '0.1.11');
define('SITEGUARD_FILE', __FILE__);
define('SITEGUARD_DIR', plugin_dir_path(__FILE__));
define('SITEGUARD_URL', plugin_dir_url(__FILE__));
define('SITEGUARD_TABLE_VERSION', '3');

// Emergency stop. Add to wp-config.php to stop enforcement and collection
// without touching the dashboard:
//   define('SITEGUARD_DISABLED', true);
if (defined('SITEGUARD_DISABLED') && SITEGUARD_DISABLED) {
    return;
}

require SITEGUARD_DIR . 'src/Core/autoload.php';

register_activation_hook(__FILE__, [\SiteGuard\Wp\Installer::class, 'activate']);
register_deactivation_hook(__FILE__, [\SiteGuard\Wp\Installer::class, 'deactivate']);

// The Plugins screen is the first place an owner looks. Put the two pages that
// matter there, plus the product site, so the plugin is reachable without
// hunting through the sidebar.
add_filter('plugin_action_links_' . plugin_basename(__FILE__), static function (array $links): array {
    $links['siteguard-overview'] = '<a href="'
        . esc_url(admin_url('admin.php?page=siteguard')) . '">Dashboard</a>';
    if (\SiteGuard\Wp\Caps::userCan(\SiteGuard\Wp\Caps::MANAGE_SETTINGS)) {
        $links['siteguard-settings'] = '<a href="'
            . esc_url(admin_url('admin.php?page=siteguard#settings')) . '">Settings</a>';
    }
    $links['siteguard-site'] = '<a href="https://randybarham.com" target="_blank"'
        . ' rel="noopener">randybarham.com</a>';
    return $links;
});

add_action('plugins_loaded', static function (): void {
    \SiteGuard\Wp\Plugin::boot();
});
