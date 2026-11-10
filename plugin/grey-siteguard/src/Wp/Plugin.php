<?php
declare(strict_types=1);

namespace SiteGuard\Wp;

/**
 * Boot order. The schema check runs first so every hook below can assume the
 * tables exist; a failed check leaves the site running with protection off
 * rather than throwing on every request.
 */
final class Plugin
{
    private static bool $booted = false;

    public static function boot(): void
    {
        if (self::$booted || !Installer::prerequisites()) {
            return;
        }
        self::$booted = true;

        try {
            Installer::install();
        } catch (\Throwable $e) {
            update_option('siteguard_last_error', [
                'at' => time(),
                'context' => 'install',
                'message' => substr($e->getMessage(), 0, 300),
            ], false);
            return;
        }

        Guard::boot();
        Tracker::boot();
        Beacon::boot();
        Retention::boot();

        if (is_admin()) {
            \SiteGuard\Wp\Admin\Menu::boot();
        }

        if (defined('WP_CLI') && WP_CLI) {
            \SiteGuard\Wp\Cli::boot();
        }
    }
}
