<?php
declare(strict_types=1);

namespace SiteGuard\Wp\Admin;

use SiteGuard\Core\Policy;
use SiteGuard\Wp\Analytics;
use SiteGuard\Wp\Caps;
use SiteGuard\Wp\Config;

/**
 * The Overview section: the 14-day traffic chart, top pages, referrers,
 * devices, and the protection coverage summary.
 */
final class Overview
{
    public static function section(): void
    {
        if (!Caps::userCan(Caps::VIEW_ANALYTICS)) {
            return;
        }

        $analytics = new Analytics($GLOBALS['wpdb']);
        $since = time() - 7 * 86400;
        $totals = $analytics->totals($since);
        $daily = $analytics->daily(time() - 14 * 86400, 14);
        $paths = $analytics->topPaths($since);
        $referrers = $analytics->topReferrers($since);
        $devices = $analytics->devices($since);
        $coverage = $analytics->coverage();
        $policy = Config::policy();

        Views::openSection('overview');
        Views::sectionTitle('Overview', 'Last 7 days unless stated otherwise.');

        if ($policy->profile() === Policy::OBSERVE) {
            Views::notice(
                'Observe-only mode is active: every request is counted and incidents are recorded, but nothing is blocked.',
                'warning'
            );
        }
        if (Config::emergencyOff()) {
            Views::notice('Protection is switched off by the emergency stop. Rules are not being applied.', 'error');
        }

        Views::stats([
            'Visitors' => number_format_i18n($totals['visitors']),
            'Reported pageviews' => number_format_i18n($totals['reported_pageviews']),
            'Sessions' => number_format_i18n($totals['sessions']),
            'Incidents' => number_format_i18n($totals['incidents']),
            'Active blocks' => number_format_i18n($totals['active_blocks']),
            'Profile' => ucfirst($policy->profile()),
        ]);

        $labels = array_map(
            static fn (array $day): string => gmdate('M j', strtotime($day['day'] . ' UTC')),
            $daily
        );

        Views::openCard('Traffic', '14 days');
        Views::areaChart(
            $labels,
            [
                [
                    'label' => 'Pageviews',
                    'tone' => 'accent',
                    'values' => array_map(static fn (array $day): int => $day['pageviews'], $daily),
                ],
                [
                    'label' => 'Visitors',
                    'tone' => 'ok',
                    'values' => array_map(static fn (array $day): int => $day['visitors'], $daily),
                ],
            ],
            'No pageviews recorded in this window.'
        );
        Views::closeCard();

        Views::openCard('Top pages', '7 days');
        Views::barList(array_map(
            static fn (array $row): array => [
                'label' => $row['path'],
                'value' => $row['views'],
                'title' => $row['path'],
            ],
            $paths
        ), 'No pageviews recorded in the last 7 days.');
        Views::closeCard();

        echo '<div class="sg-grid">';

        Views::openCard('Referrers', '7 days');
        Views::barList(array_map(
            static function (array $row): array {
                $host = wp_parse_url($row['referrer'], PHP_URL_HOST);
                $label = is_string($host) && $host !== ''
                    ? (string) preg_replace('/^www\./i', '', $host)
                    : $row['referrer'];
                return ['label' => $label, 'value' => $row['views'], 'title' => $row['referrer']];
            },
            $referrers
        ), 'No external referrers in the last 7 days.');
        Views::closeCard();

        Views::openCard('Devices', '7 days');
        $tones = ['desktop' => 'accent', 'mobile' => 'ok', 'tablet' => 'warn'];
        $segments = [];
        foreach ($devices as $row) {
            $name = $row['device'] !== '' ? $row['device'] : 'unknown';
            $segments[] = [
                'label' => ucfirst($name),
                'value' => $row['views'],
                'tone' => $tones[strtolower($name)] ?? 'muted',
            ];
        }
        Views::splitBar($segments, 'No pageviews recorded in the last 7 days.');
        Views::closeCard();

        Views::openCard('Protection coverage', 'request types');
        $statusTones = [
            'verified' => 'ok',
            'partial' => 'warn',
            'unavailable' => 'bad',
            'untested' => 'muted',
        ];
        $counts = [];
        foreach ($coverage as $row) {
            $status = (string) $row['status'];
            $counts[$status] = ($counts[$status] ?? 0) + 1;
        }
        $order = ['verified' => 0, 'partial' => 1, 'unavailable' => 2, 'untested' => 3];
        uksort($counts, static fn (string $a, string $b): int => ($order[$a] ?? 9) <=> ($order[$b] ?? 9));
        $segments = [];
        foreach ($counts as $status => $count) {
            $segments[] = [
                'label' => ucfirst($status),
                'value' => $count,
                'tone' => $statusTones[$status] ?? 'muted',
            ];
        }
        Views::splitBar($segments, 'Coverage has not been seeded in this install.');
        echo '<p class="sg-more"><a href="' . esc_url(Menu::url(Menu::OPERATIONS))
            . '">Full matrix and diagnostics</a></p>';
        Views::closeCard();

        echo '</div>';
        Views::closeSection();
    }
}
