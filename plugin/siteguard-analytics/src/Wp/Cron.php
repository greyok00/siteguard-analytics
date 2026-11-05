<?php
declare(strict_types=1);

namespace SiteGuard\Wp;

/**
 * WP-Cron jobs. Retention runs hourly in small batches so a shared host never
 * sees one enormous DELETE; an empty queue costs a single indexed query.
 */
final class Cron
{
    public const RETENTION = 'siteguard_retention';
    public const MAINTENANCE = 'siteguard_maintenance';

    public static function schedule(): void
    {
        if (!wp_next_scheduled(self::RETENTION)) {
            wp_schedule_event(time() + 300, 'hourly', self::RETENTION);
        }
        if (!wp_next_scheduled(self::MAINTENANCE)) {
            wp_schedule_event(time() + 600, 'daily', self::MAINTENANCE);
        }
    }

    public static function unschedule(): void
    {
        foreach ([self::RETENTION, self::MAINTENANCE] as $hook) {
            $timestamp = wp_next_scheduled($hook);
            while ($timestamp) {
                wp_unschedule_event($timestamp, $hook);
                $timestamp = wp_next_scheduled($hook);
            }
            wp_clear_scheduled_hook($hook);
        }
    }
}
