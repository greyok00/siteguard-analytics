<?php
declare(strict_types=1);

namespace SiteGuard\Wp\Admin;

use SiteGuard\Core\Crypto;
use SiteGuard\Core\Ip;
use SiteGuard\Core\Settings;
use SiteGuard\Core\Subjects;
use SiteGuard\Wp\Caps;
use SiteGuard\Wp\Config;
use SiteGuard\Wp\Export;
use SiteGuard\Wp\Store\WpdbAuditStore;

/**
 * admin-post handlers. Each one: capability check, nonce check, validate,
 * act, audit, redirect. A missing check here would be an authorization bug,
 * so the four steps are written out rather than abstracted.
 */
final class Actions
{
    public static function boot(): void
    {
        add_action('admin_post_siteguard_settings', [self::class, 'saveSettings']);
        add_action('admin_post_siteguard_block', [self::class, 'block']);
        add_action('admin_post_siteguard_lift', [self::class, 'lift']);
        add_action('admin_post_siteguard_emergency', [self::class, 'emergency']);
        add_action('admin_post_siteguard_export', [self::class, 'export']);
        add_action('admin_post_siteguard_export_bundle', [self::class, 'exportBundle']);
    }

    public static function saveSettings(): void
    {
        self::requireCap(Caps::MANAGE_SETTINGS);
        check_admin_referer('siteguard_settings');

        $input = wp_unslash($_POST);
        unset($input['action'], $input['_wpnonce'], $input['_wp_http_referer'], $input['submit']);
        [$clean, $errors] = Settings::sanitize((array) $input);

        if ($errors) {
            Menu::redirect(Menu::SETTINGS, implode('; ', $errors), 'error');
        }

        update_option(Settings::OPTION, $clean);
        Config::forget();
        delete_transient(WafProbe::cacheKey());
        delete_transient('siteguard_collector_probe');
        self::audit('settings.saved', 'settings', ['profile' => $clean['profile'], 'waf_profile' => $clean['waf_profile']]);
        Menu::redirect(Menu::SETTINGS, 'Settings saved.');
    }

    public static function block(): void
    {
        self::requireCap(Caps::MANAGE_BLOCKS);
        check_admin_referer('siteguard_block');

        $raw = trim(sanitize_text_field(wp_unslash((string) ($_POST['subject'] ?? ''))));
        $hours = max(1, min(168, absint(wp_unslash($_POST['hours'] ?? 1))));
        $reason = substr(sanitize_text_field(wp_unslash((string) ($_POST['reason'] ?? ''))), 0, 191);

        $subject = self::normaliseSubject($raw);
        if ($subject === null) {
            Menu::redirect(Menu::SECURITY, 'That address or visitor id is not valid.', 'error');
        }

        $now = time();
        $scope = str_starts_with($subject, Subjects::ACCOUNT_PREFIX)
            ? 'account'
            : (str_starts_with($subject, Subjects::VISITOR_PREFIX) ? 'visitor' : 'ip');

        $id = Config::blocks()->add(
            $subject,
            $scope,
            $reason !== '' ? $reason : 'manual block',
            'manual',
            ['by' => get_current_user_id()],
            $now,
            $now + $hours * 3600,
            'admin:' . get_current_user_id()
        );

        self::audit('block.created', $subject, ['hours' => $hours, 'block_id' => $id]);
        Menu::redirect(
            Menu::SECURITY,
            $id > 0 ? 'Block applied.' : 'That subject already has an active block.'
        );
    }

    public static function lift(): void
    {
        self::requireCap(Caps::MANAGE_BLOCKS);
        check_admin_referer('siteguard_lift');

        $subject = self::normaliseSubject(trim(sanitize_text_field(wp_unslash((string) ($_POST['subject'] ?? '')))));
        if ($subject === null) {
            Menu::redirect(Menu::SECURITY, 'That subject is not valid.', 'error');
        }

        $lifted = Config::blocks()->lift($subject, time());
        self::audit('block.lifted', $subject, ['lifted' => $lifted]);
        Menu::redirect(Menu::SECURITY, $lifted ? 'Block lifted.' : 'No active block for that subject.');
    }

    public static function emergency(): void
    {
        self::requireCap(Caps::MANAGE_SETTINGS);
        check_admin_referer('siteguard_emergency');

        $enabled = sanitize_key(wp_unslash((string) ($_POST['enabled'] ?? '0'))) === '1';
        update_option('siteguard_emergency_off', $enabled, false);
        self::audit($enabled ? 'protection.stopped' : 'protection.resumed', 'emergency', []);
        Menu::redirect(
            Menu::OPERATIONS,
            $enabled ? 'Protection stopped.' : 'Protection resumed.'
        );
    }

    public static function export(): void
    {
        self::requireCap(Caps::EXPORT_DATA);
        check_admin_referer('siteguard_export');

        $type = sanitize_key((string) ($_GET['type'] ?? ''));
        self::audit('data.exported', $type, []);
        Export::stream($type);
    }

    /**
     * One file holding every table, for analysis outside WordPress. The
     * plugin never sends this anywhere; the owner downloads it and decides.
     */
    public static function exportBundle(): void
    {
        self::requireCap(Caps::EXPORT_DATA);
        check_admin_referer('siteguard_export');

        self::audit('data.exported', 'bundle', []);
        Export::streamBundle();
    }

    private static function requireCap(string $capability): void
    {
        if (!Caps::userCan($capability)) {
            wp_die(esc_html('You do not have permission to do that.'), 403);
        }
    }

    private static function audit(string $action, string $target, array $details): void
    {
        (new WpdbAuditStore($GLOBALS['wpdb']))->record(
            (int) get_current_user_id(),
            $action,
            $target,
            $details,
            time()
        );
    }

    /** Accepts an address or an existing subject/visitor id. */
    private static function normaliseSubject(string $raw): ?string
    {
        if ($raw === '') {
            return null;
        }
        if (str_starts_with($raw, Subjects::ACCOUNT_PREFIX)) {
            $id = (int) substr($raw, 2);
            return $id > 0 ? Subjects::account($id) : null;
        }
        if (str_starts_with($raw, Subjects::VISITOR_PREFIX)) {
            $id = substr($raw, 2);
            return Crypto::isId($id) ? Subjects::visitor($id) : null;
        }
        if (str_starts_with($raw, 'ip4:') || str_starts_with($raw, 'ip6:')) {
            return substr($raw, 0, 48);
        }
        if (Crypto::isId($raw)) {
            return Subjects::visitor($raw);
        }
        $ip = Ip::normalize($raw);
        return $ip === null ? null : Subjects::ip(Ip::subject($ip));
    }
}
