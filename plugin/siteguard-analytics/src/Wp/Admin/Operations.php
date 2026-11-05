<?php
declare(strict_types=1);

namespace SiteGuard\Wp\Admin;

use SiteGuard\Wp\Analytics;
use SiteGuard\Wp\Caps;
use SiteGuard\Wp\Config;
use SiteGuard\Wp\Installer;
use SiteGuard\Wp\Store\WpdbAuditStore;

/**
 * The Operations section: the coverage matrix, diagnostics, CSV and JSON
 * exports, the emergency stop, and the audit log.
 */
final class Operations
{
    public static function section(): void
    {
        if (!Caps::userCan(Caps::VIEW_SECURITY)) {
            return;
        }

        $analytics = new Analytics($GLOBALS['wpdb']);
        $settings = Config::settings();
        $lastError = get_option('siteguard_last_error');
        $lastRetention = get_option('siteguard_last_retention');
        $audit = (new WpdbAuditStore($GLOBALS['wpdb']))->recent(40, 0);

        Views::openSection('operations');
        Views::sectionTitle('Operations', 'What is protected, what is not, and what the plugin has been doing.');

        Views::openCard('Coverage matrix');
        $rows = [];
        foreach ($analytics->coverage() as $row) {
            $tested = $row['tested_at']
                ? sprintf('%s ago', human_time_diff((int) strtotime((string) $row['tested_at'] . ' UTC'), time()))
                : '—';
            $rows[] = [
                esc_html((string) $row['class']),
                Views::badge((string) $row['status']),
                esc_html((string) $row['reason']),
                esc_html($tested),
            ];
        }
        Views::table(['Request type', 'Status', 'Why', 'Last verified'], $rows);
        Views::closeCard();

        Views::openCard('Diagnostics');
        $tables = Installer::tables();
        $missing = [];
        foreach ($tables as $name) {
            if ($GLOBALS['wpdb']->get_var($GLOBALS['wpdb']->prepare('SHOW TABLES LIKE %s', $name)) !== $name) {
                $missing[] = $name;
            }
        }
        $rows = [
            ['Schema version', esc_html((string) get_option(Installer::SCHEMA_OPTION, '0'))],
            ['Plugin version', esc_html(SITEGUARD_VERSION)],
            ['Enforcement', esc_html(Config::emergencyOff() ? 'off (emergency stop)' : 'on')],
            ['Missing tables', $missing ? esc_html(implode(', ', $missing)) : esc_html('none')],
            ['Last error', $lastError && is_array($lastError)
                ? esc_html(sprintf('%s ago: %s', human_time_diff((int) $lastError['at'], time()), $lastError['message']))
                : esc_html('none')],
            ['Last retention run', $lastRetention && isset($lastRetention['at'])
                ? esc_html(sprintf('%s ago', human_time_diff((int) $lastRetention['at'], time())))
                : esc_html('not yet run')],
            ['Trusted proxies', esc_html(($settings['trusted_proxies'] ?? '') !== '' ? $settings['trusted_proxies'] : 'none configured')],
            ['IP storage', esc_html((string) $settings['ip_storage'])],
        ];
        Views::table(['Check', 'Value'], array_map(
            static fn (array $r): array => [esc_html($r[0]), $r[1]],
            $rows
        ));
        Views::closeCard();

        if (Caps::userCan(Caps::MANAGE_SETTINGS)) {
            Views::openCard('Emergency stop');
            Views::formOpen('siteguard_emergency', 'siteguard_emergency');
            echo '<input type="hidden" name="enabled" value="' . (Config::emergencyOff() ? '0' : '1') . '">';
            echo '<p>Current state: <strong>' . (Config::emergencyOff() ? 'stopped' : 'running') . '</strong></p>';
            Views::formClose(Config::emergencyOff() ? 'Resume protection' : 'Stop protection');
            Views::closeCard();
        }

        Views::openCard('Exports');
        echo '<p class="sg-lead">Generated on demand; nothing is stored and nothing is sent anywhere. Spreadsheet formulas are neutralised.</p>';
        echo '<p>';
        foreach ([
            'events' => 'Events',
            'sessions' => 'Sessions',
            'visitors' => 'Visitors',
            'incidents' => 'Incidents',
            'blocks' => 'Blocks',
            'audit' => 'Audit log',
        ] as $key => $label) {
            if (!Caps::userCan(Caps::EXPORT_DATA)) {
                break;
            }
            $url = wp_nonce_url(
                admin_url('admin-post.php?action=siteguard_export&type=' . $key),
                'siteguard_export'
            );
            echo '<a class="button" href="' . esc_url($url) . '">' . esc_html($label) . '</a> ';
        }
        echo '</p>';
        if (Caps::userCan(Caps::EXPORT_DATA)) {
            echo '<p class="sg-lead"><strong>One file for analysis.</strong> A single JSON document with every table, '
                . 'capped at 2,000 rows each, newest first. Download it yourself and take it to whichever tool you prefer; '
                . 'the plugin has no model connection and never uploads anything.</p>';
            $bundle = wp_nonce_url(
                admin_url('admin-post.php?action=siteguard_export_bundle'),
                'siteguard_export'
            );
            echo '<p><a class="button button-primary" href="' . esc_url($bundle) . '">Download JSON bundle</a></p>';
        }
        Views::closeCard();

        if (Caps::userCan(Caps::VIEW_AUDIT)) {
            Views::openCard('Audit log');
            $rows = [];
            foreach ($audit as $entry) {
                $rows[] = [
                    esc_html(sprintf('%s ago', human_time_diff((int) strtotime((string) $entry['ts'] . ' UTC'), time()))),
                    esc_html((string) $entry['action']),
                    esc_html((string) $entry['target']),
                    esc_html((string) $entry['actor_id']),
                ];
            }
            Views::table(['When', 'Action', 'Target', 'Actor'], $rows, 'No privileged actions recorded yet.');
            Views::closeCard();
        }

        Views::closeSection();
    }
}
