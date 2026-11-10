<?php
declare(strict_types=1);

namespace SiteGuard\Wp;

use SiteGuard\Wp\Store\WpdbAuditStore;
use SiteGuard\Wp\Store\WpdbBlockStore;
use SiteGuard\Wp\Store\WpdbCounterStore;
use SiteGuard\Wp\Store\WpdbDistinctStore;
use SiteGuard\Wp\Store\WpdbEventStore;
use SiteGuard\Wp\Store\WpdbIncidentStore;
use SiteGuard\Wp\Store\WpdbPeopleStore;

/**
 * Hourly retention in small batches. Each table keeps only its configured
 * window, so storage is bounded without a background worker.
 */
final class Retention
{
    public static function boot(): void
    {
        add_action(Cron::RETENTION, [self::class, 'run']);
        add_action(Cron::MAINTENANCE, [self::class, 'maintain']);
    }

    public static function run(): void
    {
        if (!Installer::ready()) {
            return;
        }
        $policy = Config::policy();
        $now = time();
        $db = $GLOBALS['wpdb'];
        $done = [];

        $done['counters'] = (new WpdbCounterStore($db))->prune(1000);
        $done['distinct'] = (new WpdbDistinctStore($db))->prune($now - 86400);
        $done['blocks'] = (new WpdbBlockStore($db))->prune($now, 500);
        $done['events'] = (new WpdbEventStore($db))->pruneBefore($now - $policy->retentionDays('events') * 86400);
        $done['incidents'] = (new WpdbIncidentStore($db))->pruneBefore($now - $policy->retentionDays('incidents') * 86400);
        $done['audit'] = (new WpdbAuditStore($db))->pruneBefore($now - $policy->retentionDays('audit') * 86400);
        $done['people'] = (new WpdbPeopleStore($db))->pruneBefore($now - $policy->retentionDays('sessions') * 86400);

        update_option('siteguard_last_retention', ['at' => $now, 'deleted' => $done], false);
    }

    public static function maintain(): void
    {
        update_option('siteguard_last_maintenance', time(), false);
    }
}
