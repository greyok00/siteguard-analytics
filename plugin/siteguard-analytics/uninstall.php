<?php
/**
 * Uninstall routine.
 *
 * Deleting a site's security history should be a deliberate act. The tables
 * and options are removed only when wp-config.php contains:
 *
 *     define('SITEGUARD_REMOVE_DATA', true);
 *
 * Without it, deactivating and deleting the plugin leaves the data in place so
 * the plugin can be reinstalled without losing incidents or the audit log.
 */

declare(strict_types=1);

if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

if (!defined('SITEGUARD_REMOVE_DATA') || !SITEGUARD_REMOVE_DATA) {
    return;
}

global $wpdb;

$siteguard_prefix = $wpdb->prefix . 'sg_';
$siteguard_tables = [
    'events', 'sessions', 'visitors', 'identities', 'counters', 'distinct',
    'blocks', 'incidents', 'audit', 'coverage', 'ai_usage', 'ai_confirmations',
];
foreach ($siteguard_tables as $siteguard_table) {
    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange -- uninstall removes the plugin's own tables when SITEGUARD_REMOVE_DATA is set.
    $wpdb->query($wpdb->prepare('DROP TABLE IF EXISTS %i', $siteguard_prefix . $siteguard_table));
}

$siteguard_options = [
    'siteguard_settings',
    'siteguard_schema_version',
    'siteguard_salt',
    'siteguard_fp_salt',
    'siteguard_fp_version',
    'siteguard_emergency_off',
    'siteguard_last_error',
    'siteguard_last_retention',
    'siteguard_last_maintenance',
];
foreach ($siteguard_options as $siteguard_option) {
    delete_option($siteguard_option);
}

wp_clear_scheduled_hook('siteguard_retention');
wp_clear_scheduled_hook('siteguard_maintenance');

$siteguard_role = get_role('administrator');
if ($siteguard_role) {
    foreach ([
        'sg_view_analytics', 'sg_view_security', 'sg_manage_blocks', 'sg_manage_rules',
        'sg_manage_settings', 'sg_export_data', 'sg_manage_ai', 'sg_view_audit',
    ] as $siteguard_cap) {
        $siteguard_role->remove_cap($siteguard_cap);
    }
}
