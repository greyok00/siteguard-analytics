<?php
declare(strict_types=1);

namespace SiteGuard\Wp;

use SiteGuard\Core\Crypto;
use SiteGuard\Core\Enforcer;
use SiteGuard\Core\Policy;
use SiteGuard\Core\Settings;
use SiteGuard\Core\Store\Blocks;
use SiteGuard\Core\Store\Counters;
use SiteGuard\Core\Store\Distinct;
use SiteGuard\Core\Store\Incidents;
use SiteGuard\Core\SystemClock;
use SiteGuard\Core\Waf\Gate;
use SiteGuard\Wp\Store\WpdbBlockStore;
use SiteGuard\Wp\Store\WpdbCounterStore;
use SiteGuard\Wp\Store\WpdbDistinctStore;
use SiteGuard\Wp\Store\WpdbIncidentStore;

/**
 * Lazily built services shared by the request path and the admin screens.
 * Each store is created once per request; the settings option is read once.
 */
final class Config
{
    private static ?array $settings = null;
    private static ?Crypto $crypto = null;
    private static ?Counters $counters = null;
    private static ?Distinct $distinct = null;
    private static ?Blocks $blocks = null;
    private static ?Incidents $incidents = null;
    private static ?Enforcer $enforcer = null;
    private static ?Gate $wafGate = null;

    public static function settings(): array
    {
        if (self::$settings === null) {
            $stored = get_option(Settings::OPTION);
            self::$settings = Settings::from(is_array($stored) ? $stored : []);
        }
        return self::$settings;
    }

    /** Drop the cached copy after a settings save in the same request. */
    public static function forget(): void
    {
        self::$settings = null;
        self::$enforcer = null;
        self::$wafGate = null;
    }

    public static function policy(): Policy
    {
        return new Policy(self::settings());
    }

    public static function crypto(): Crypto
    {
        if (self::$crypto === null) {
            $site = (string) get_option(Installer::SALT_OPTION, '');
            $fp = (string) get_option(Installer::FINGERPRINT_SALT_OPTION, '');
            $version = (int) get_option(Installer::FP_VERSION_OPTION, 1);
            self::$crypto = new Crypto($site, $fp, max(1, $version));
        }
        return self::$crypto;
    }

    public static function clock(): SystemClock
    {
        return new SystemClock();
    }

    public static function counters(): Counters
    {
        return self::$counters ??= new WpdbCounterStore($GLOBALS['wpdb']);
    }

    public static function distinct(): Distinct
    {
        return self::$distinct ??= new WpdbDistinctStore($GLOBALS['wpdb']);
    }

    public static function blocks(): Blocks
    {
        return self::$blocks ??= new WpdbBlockStore($GLOBALS['wpdb']);
    }

    public static function incidents(): Incidents
    {
        return self::$incidents ??= new WpdbIncidentStore($GLOBALS['wpdb']);
    }

    public static function enforcer(): Enforcer
    {
        if (self::$enforcer === null) {
            self::$enforcer = new Enforcer(
                self::policy(),
                self::counters(),
                self::distinct(),
                self::blocks(),
                self::clock(),
                self::incidents()
            );
        }
        return self::$enforcer;
    }

    public static function wafGate(): Gate
    {
        if (self::$wafGate === null) {
            $settings = self::settings();
            self::$wafGate = new Gate(
                (string) ($settings['waf_profile'] ?? 'observe'),
                new Policy($settings),
                self::incidents(),
                self::blocks(),
                self::clock()
            );
        }
        return self::$wafGate;
    }

    /**
     * Emergency stop. Honours a constant, an option, and a filter so a host
     * can disable enforcement without editing the plugin.
     */
    public static function emergencyOff(): bool
    {
        if (defined('SITEGUARD_DISABLED') && SITEGUARD_DISABLED) {
            return true;
        }
        if ((bool) get_option('siteguard_emergency_off', false)) {
            return true;
        }
        return (bool) apply_filters('siteguard_emergency_disabled', false);
    }
}
