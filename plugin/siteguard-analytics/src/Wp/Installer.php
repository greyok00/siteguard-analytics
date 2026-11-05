<?php
declare(strict_types=1);

namespace SiteGuard\Wp;

use SiteGuard\Core\Crypto;
use SiteGuard\Core\Settings;

/**
 * Activation, schema migrations, capabilities, and scheduled jobs.
 *
 * Migrations are additive and idempotent: dbDelta creates missing tables and
 * columns, and the stored version only moves forward once the schema is in
 * place. A failed migration leaves the old tables untouched.
 */
final class Installer
{
    public const SCHEMA_OPTION = 'siteguard_schema_version';
    public const SALT_OPTION = 'siteguard_salt';
    public const FINGERPRINT_SALT_OPTION = 'siteguard_fp_salt';
    public const FP_VERSION_OPTION = 'siteguard_fp_version';

    public static function activate(): void
    {
        if (!self::prerequisites()) {
            deactivate_plugins(plugin_basename(SITEGUARD_FILE));
            wp_die(
                esc_html('SiteGuard Analytics needs WordPress 6.4+, PHP 8.1+, and the $wpdb layer. It was not activated.'),
                'SiteGuard Analytics',
                ['back_link' => true]
            );
        }

        self::install();
        self::capabilities();

        if (!get_option(Settings::OPTION)) {
            add_option(Settings::OPTION, Settings::defaults());
        }
        if (!get_option(self::SALT_OPTION)) {
            add_option(self::SALT_OPTION, Crypto::randomSecret(), '', false);
        }
        if (!get_option(self::FINGERPRINT_SALT_OPTION)) {
            add_option(self::FINGERPRINT_SALT_OPTION, Crypto::randomSecret(), '', false);
        }
        if (!get_option(self::FP_VERSION_OPTION)) {
            add_option(self::FP_VERSION_OPTION, 1, '', false);
        }

        Cron::schedule();
    }

    public static function deactivate(): void
    {
        Cron::unschedule();
        // Historical data stays; uninstall.php removes it only on request.
    }

    public static function prerequisites(): bool
    {
        global $wpdb;
        return PHP_VERSION_ID >= 80100
            && version_compare(get_bloginfo('version'), '6.4', '>=')
            && $wpdb instanceof \wpdb;
    }

    /** Runs pending migrations. Safe to call on every load; cheap when current. */
    public static function install(): void
    {
        $installed = (string) get_option(self::SCHEMA_OPTION, '0');
        if (version_compare($installed, SITEGUARD_TABLE_VERSION, '>=')) {
            return;
        }
        self::migrate();
        self::upgradeSettings();
        update_option(self::SCHEMA_OPTION, SITEGUARD_TABLE_VERSION, true);
    }

    /**
     * One-time settings move for schema 2: the plugin now stores the visitor's
     * address so the dashboard can identify a row, and the assistant block was
     * removed. An install still on the old default is moved to "full"; an
     * owner who later picks "hashed" keeps that choice.
     */
    private static function upgradeSettings(): void
    {
        if ((string) get_option('siteguard_settings_version', '0') === '2') {
            return;
        }
        $stored = get_option(Settings::OPTION, null);
        if (is_array($stored)) {
            $changed = false;
            if (array_key_exists('ai', $stored)) {
                unset($stored['ai']);
                $changed = true;
            }
            if (($stored['ip_storage'] ?? '') === 'hashed') {
                $stored['ip_storage'] = 'full';
                $changed = true;
            }
            if ($changed) {
                update_option(Settings::OPTION, Settings::from($stored));
            }
        }
        update_option('siteguard_settings_version', '2', false);
    }

    public static function tables(): array
    {
        global $wpdb;
        $p = $wpdb->prefix . 'sg_';
        return [
            'events' => $p . 'events',
            'sessions' => $p . 'sessions',
            'visitors' => $p . 'visitors',
            'identities' => $p . 'identities',
            'counters' => $p . 'counters',
            'distinct' => $p . 'distinct',
            'blocks' => $p . 'blocks',
            'incidents' => $p . 'incidents',
            'audit' => $p . 'audit',
            'coverage' => $p . 'coverage',
        ];
    }

    private static function migrate(): void
    {
        global $wpdb;
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        $charset = $wpdb->get_charset_collate();
        $t = self::tables();

        $sql = [];

        // Browser-reported and server-observed events share this table but are
        // separated by `source`, so a fabricated pageview is never counted as a
        // server request.
        $sql[] = "CREATE TABLE {$t['events']} (
            id bigint unsigned NOT NULL AUTO_INCREMENT,
            ts datetime NOT NULL,
            source varchar(12) NOT NULL DEFAULT 'browser',
            type varchar(32) NOT NULL,
            visitor char(32) NOT NULL DEFAULT '',
            session char(32) NOT NULL DEFAULT '',
            account_id bigint unsigned NOT NULL DEFAULT 0,
            path varchar(255) NOT NULL DEFAULT '',
            referrer varchar(255) NOT NULL DEFAULT '',
            ua_hash char(32) NOT NULL DEFAULT '',
            device varchar(20) NOT NULL DEFAULT '',
            browser varchar(40) NOT NULL DEFAULT '',
            ip varchar(45) NOT NULL DEFAULT '',
            ua varchar(400) NOT NULL DEFAULT '',
            profile mediumtext NULL,
            meta text NULL,
            dedupe char(40) NULL DEFAULT NULL,
            ip_hash char(40) NOT NULL DEFAULT '',
            PRIMARY KEY  (id),
            KEY ts (ts),
            KEY visitor_ts (visitor,ts),
            KEY session (session),
            KEY type_ts (type,ts),
            KEY source_ts (source,ts),
            KEY ip_ts (ip,ts),
            UNIQUE KEY dedupe (dedupe)
        ) $charset;";

        $sql[] = "CREATE TABLE {$t['sessions']} (
            id char(32) NOT NULL,
            visitor char(32) NOT NULL DEFAULT '',
            account_id bigint unsigned NOT NULL DEFAULT 0,
            started_at datetime NOT NULL,
            last_seen datetime NOT NULL,
            pageviews int unsigned NOT NULL DEFAULT 0,
            landing varchar(255) NOT NULL DEFAULT '',
            exit_path varchar(255) NOT NULL DEFAULT '',
            device varchar(20) NOT NULL DEFAULT '',
            browser varchar(40) NOT NULL DEFAULT '',
            ip varchar(45) NOT NULL DEFAULT '',
            ua varchar(400) NOT NULL DEFAULT '',
            ip_hash char(40) NOT NULL DEFAULT '',
            PRIMARY KEY  (id),
            KEY last_seen (last_seen),
            KEY visitor (visitor),
            KEY account_id (account_id),
            KEY ip (ip)
        ) $charset;";

        // ip, ua, profile, and last_path are the latest values seen for this
        // visitor; the events table keeps the full history.
        $sql[] = "CREATE TABLE {$t['visitors']} (
            id char(32) NOT NULL,
            first_seen datetime NOT NULL,
            last_seen datetime NOT NULL,
            sessions int unsigned NOT NULL DEFAULT 0,
            pageviews int unsigned NOT NULL DEFAULT 0,
            ip varchar(45) NOT NULL DEFAULT '',
            ua varchar(400) NOT NULL DEFAULT '',
            profile mediumtext NULL,
            last_path varchar(255) NOT NULL DEFAULT '',
            PRIMARY KEY  (id),
            KEY last_seen (last_seen),
            KEY ip (ip)
        ) $charset;";

        // Correlated, never merged: one row per (pseudonymous browser, account)
        // pair with the first and last sighting.
        $sql[] = "CREATE TABLE {$t['identities']} (
            visitor char(32) NOT NULL,
            account_id bigint unsigned NOT NULL,
            first_seen datetime NOT NULL,
            last_seen datetime NOT NULL,
            PRIMARY KEY  (visitor,account_id),
            KEY account_id (account_id)
        ) $charset;";

        // Atomic counters. `k` encodes profile class, subject, and window start;
        // rows are deleted after `expires_at` by the retention job.
        $sql[] = "CREATE TABLE {$t['counters']} (
            k varchar(191) NOT NULL,
            n bigint unsigned NOT NULL DEFAULT 0,
            expires_at datetime NOT NULL,
            PRIMARY KEY  (k),
            KEY expires_at (expires_at)
        ) $charset;";

        // Distinct-path coverage per subject and window.
        $sql[] = "CREATE TABLE {$t['distinct']} (
            subject varchar(48) NOT NULL,
            path_hash char(16) NOT NULL,
            window_start bigint unsigned NOT NULL,
            PRIMARY KEY  (subject,path_hash,window_start),
            KEY window_start (window_start)
        ) $charset;";

        $sql[] = "CREATE TABLE {$t['blocks']} (
            id bigint unsigned NOT NULL AUTO_INCREMENT,
            subject varchar(48) NOT NULL,
            scope varchar(16) NOT NULL DEFAULT 'ip',
            reason varchar(191) NOT NULL DEFAULT '',
            rule varchar(64) NOT NULL DEFAULT '',
            evidence text NULL,
            created_at datetime NOT NULL,
            expires_at datetime NOT NULL,
            created_by varchar(32) NOT NULL DEFAULT 'system',
            lifted_at datetime NULL DEFAULT NULL,
            PRIMARY KEY  (id),
            UNIQUE KEY subject (subject),
            KEY expires_at (expires_at)
        ) $charset;";

        $sql[] = "CREATE TABLE {$t['incidents']} (
            id bigint unsigned NOT NULL AUTO_INCREMENT,
            ts datetime NOT NULL,
            subject varchar(48) NOT NULL,
            rule varchar(64) NOT NULL DEFAULT '',
            severity varchar(16) NOT NULL DEFAULT 'medium',
            evidence text NULL,
            request_count int unsigned NOT NULL DEFAULT 0,
            block_id bigint unsigned NOT NULL DEFAULT 0,
            resolved_at datetime NULL DEFAULT NULL,
            PRIMARY KEY  (id),
            KEY ts (ts),
            KEY subject (subject),
            KEY rule_ts (rule,ts)
        ) $charset;";

        $sql[] = "CREATE TABLE {$t['audit']} (
            id bigint unsigned NOT NULL AUTO_INCREMENT,
            ts datetime NOT NULL,
            actor_id bigint unsigned NOT NULL DEFAULT 0,
            action varchar(64) NOT NULL,
            target varchar(191) NOT NULL DEFAULT '',
            details text NULL,
            PRIMARY KEY  (id),
            KEY ts (ts),
            KEY actor (actor_id)
        ) $charset;";

        // One row per request class the plugin knows about; status is honest
        // about what it can and cannot intercept.
        $sql[] = "CREATE TABLE {$t['coverage']} (
            class varchar(24) NOT NULL,
            status varchar(16) NOT NULL DEFAULT 'untested',
            reason varchar(191) NOT NULL DEFAULT '',
            tested_at datetime NULL DEFAULT NULL,
            PRIMARY KEY  (class)
        ) $charset;";

        foreach ($sql as $statement) {
            dbDelta($statement);
        }

        self::seedCoverage();
    }

    private static function seedCoverage(): void
    {
        global $wpdb;
        $table = self::tables()['coverage'];
        $rows = [
            ['html', 'untested', 'Not exercised on this install'],
            ['search', 'untested', 'Not exercised on this install'],
            ['feed', 'untested', 'Not exercised on this install'],
            ['rest', 'untested', 'Not exercised on this install'],
            ['ajax', 'untested', 'Not exercised on this install'],
            ['api', 'partial', 'WooCommerce Store API and webhooks are exempt from HTML limits'],
            ['login', 'untested', 'Not exercised on this install'],
            ['cart', 'untested', 'Not exercised on this install'],
            ['checkout', 'untested', 'Not exercised on this install'],
            ['download', 'untested', 'Not exercised on this install'],
            ['admin', 'unavailable', 'wp-admin is excluded so a rule error cannot lock the owner out'],
            ['cached', 'unavailable', 'Page caches that serve HTML without PHP bypass every plugin hook'],
            ['static', 'unavailable', 'Files served directly by the web server never reach WordPress'],
            ['cron', 'unavailable', 'wp-cron requests are not visitor traffic'],
        ];
        foreach ($rows as [$class, $status, $reason]) {
            // Same effect as INSERT IGNORE: the class column is the primary
            // key, so reseeding rewrites the row instead of duplicating it.
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- seeds the plugin's own coverage table; there is no core API for it.
            $wpdb->insert($table, [
                'class' => $class,
                'status' => $status,
                'reason' => $reason,
            ]);
        }
    }

    public static function capabilities(): void
    {
        Caps::install();
    }

    /** True when the tables exist; guards every runtime query. */
    public static function ready(): bool
    {
        static $ready = null;
        if ($ready !== null) {
            return $ready;
        }
        global $wpdb;
        $table = $wpdb->prefix . 'sg_counters';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- SHOW TABLES has no core API and the answer is memoised in the static above.
        $ready = $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $table)) === $table;
        return $ready;
    }
}
