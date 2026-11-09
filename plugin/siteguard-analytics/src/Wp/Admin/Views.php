<?php
declare(strict_types=1);

namespace SiteGuard\Wp\Admin;

use SiteGuard\Wp\Caps;

/**
 * Small rendering helpers. Every value is escaped here rather than at each
 * call site, so a page cannot forget one.
 */
final class Views
{
    /** The product site every plugin page links back to. */
    public const SITE_URL = 'https://randybarham.com';

    /**
     * The shield mark, drawn inline: outlined shield with a check. Same grey
     * tile treatment as the assistant's wolf so the two plugins match, with a
     * shape that is unmistakably its own.
     *
     * Printed straight to the page: the markup is a fixed literal, and passing
     * it through wp_kses would lowercase `viewBox` and break the drawing.
     */
    public static function mark(): void
    {
        echo '<span class="sg-logo" aria-hidden="true">'
            . '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"'
            . ' stroke-linecap="round" stroke-linejoin="round">'
            . '<path d="M12 2.4 20 5.4v6.3c0 4.9-3.3 8.5-8 9.9-4.7-1.4-8-5-8-9.9V5.4Z"'
            . ' fill="currentColor" fill-opacity=".12"/>'
            . '<path d="m8.5 11.9 2.4 2.4 4.6-4.8"/>'
            . '</svg></span>';
    }

    /**
     * The tab strip. These are real anchors, so a page without JavaScript
     * still jumps to each section; the admin script turns them into tabs.
     */
    private static function nav(): string
    {
        $items = [
            ['overview', 'Overview', Caps::VIEW_ANALYTICS],
            [Menu::VISITORS, 'Visitors', Caps::VIEW_ANALYTICS],
            [Menu::PROFILES, 'Profiles', Caps::VIEW_ANALYTICS],
            [Menu::SECURITY, 'Security', Caps::VIEW_SECURITY],
            [Menu::OPERATIONS, 'Operations', Caps::VIEW_SECURITY],
            [Menu::SETTINGS, 'Settings', Caps::MANAGE_SETTINGS],
            ['faq', 'FAQ', Caps::VIEW_ANALYTICS],
        ];

        $out = '<nav class="sg-nav" role="tablist" aria-label="Sections on this page">';
        $first = true;
        foreach ($items as [$anchor, $label, $cap]) {
            if (!Caps::userCan($cap)) {
                continue;
            }
            $active = $first ? ' is-on' : '';
            $selected = $first ? 'true' : 'false';
            $out .= '<a class="sg-tab' . $active . '" id="sg-tab-' . esc_attr($anchor) . '"'
                . ' href="#' . esc_attr($anchor) . '" role="tab"'
                . ' aria-controls="' . esc_attr($anchor) . '"'
                . ' aria-selected="' . $selected . '"'
                . ' data-sg-tab="' . esc_attr($anchor) . '">' . esc_html($label) . '</a>';
            $first = false;
        }
        return $out . '</nav>';
    }

    /** Opens a section on the single page. The id is the anchor the nav uses. */
    public static function openSection(string $id): void
    {
        echo '<section class="sg-section" id="' . esc_attr($id) . '" role="tabpanel"'
            . ' aria-labelledby="sg-tab-' . esc_attr($id) . '">';
    }

    public static function closeSection(): void
    {
        echo '</section>';
    }

    public static function sectionTitle(string $title, string $subtitle = ''): void
    {
        echo '<h2 class="sg-section-title">' . esc_html($title) . '</h2>';
        if ($subtitle !== '') {
            echo '<p class="sg-sub">' . esc_html($subtitle) . '</p>';
        }
    }

    public static function pageTitle(string $title, string $subtitle = ''): void
    {
        echo '<header class="sg-head">';
        echo '<div class="sg-brand">';
        self::mark();
        echo '<span class="sg-word"><span class="sg-wordmark">SiteGuard <em>Analytics</em></span>';
        echo '<span class="sg-kicker">Request protection and first-party analytics</span></span>';
        echo '<a class="sg-site" href="' . esc_url(self::SITE_URL) . '" target="_blank"'
            . ' rel="noopener">randybarham.com <span aria-hidden="true">&nearr;</span></a>';
        echo '</div>';
        echo '<div class="sg-title"><h1>' . esc_html($title) . '</h1>';
        if ($subtitle !== '') {
            echo '<p class="sg-sub">' . esc_html($subtitle) . '</p>';
        }
        echo '</div>';
        echo wp_kses(self::nav(), [
            'nav' => ['class' => true, 'role' => true, 'aria-label' => true],
            'a' => [
                'class' => true,
                'id' => true,
                'href' => true,
                'role' => true,
                'aria-controls' => true,
                'aria-selected' => true,
                'data-sg-tab' => true,
            ],
        ]);
        echo '</header>';
    }

    public static function openCard(string $title = '', string $meta = ''): void
    {
        echo '<div class="sg-card">';
        if ($title !== '') {
            echo '<div class="sg-card-head"><h3>' . esc_html($title) . '</h3>';
            if ($meta !== '') {
                echo '<span class="sg-card-meta">' . esc_html($meta) . '</span>';
            }
            echo '</div>';
        }
    }

    public static function closeCard(): void
    {
        echo '</div>';
    }

    /** @param array<string,string> $stats label => value */
    public static function stats(array $stats): void
    {
        echo '<div class="sg-stats">';
        foreach ($stats as $label => $value) {
            echo '<div class="sg-stat"><span class="sg-stat-value">' . esc_html($value) . '</span>';
            echo '<span class="sg-stat-label">' . esc_html($label) . '</span></div>';
        }
        echo '</div>';
    }

    /** @param list<string> $headers @param list<list<string>> $rows */
    public static function table(array $headers, array $rows, string $empty = 'Nothing recorded yet.'): void
    {
        if (!$rows) {
            echo '<p class="sg-empty">' . esc_html($empty) . '</p>';
            return;
        }
        // The wrapper scrolls on a phone. The table itself stays a real table
        // at 100% width, so it fills its card instead of shrinking to the
        // length of the text in the first column.
        echo '<div class="sg-table-wrap"><table class="widefat striped sg-table"><thead><tr>';
        foreach ($headers as $header) {
            echo '<th scope="col">' . esc_html($header) . '</th>';
        }
        echo '</tr></thead><tbody>';
        foreach ($rows as $row) {
            echo '<tr>';
            foreach ($row as $cell) {
                // Cells are pre-escaped by the caller when they contain
                // markup; kses keeps the links, badges, and code tags.
                echo '<td>' . wp_kses_post($cell) . '</td>';
            }
            echo '</tr>';
        }
        echo '</tbody></table></div>';
    }

    public static function badge(string $status): string
    {
        $map = [
            'verified' => 'ok',
            'partial' => 'warn',
            'unavailable' => 'bad',
            'untested' => 'muted',
            'high' => 'bad',
            'medium' => 'warn',
            'low' => 'muted',
        ];
        $class = $map[$status] ?? 'muted';
        return '<span class="sg-badge sg-' . esc_attr($class) . '">' . esc_html($status) . '</span>';
    }

    public static function notice(string $message, string $type = 'success'): void
    {
        echo '<div class="notice notice-' . esc_attr($type) . ' is-dismissible"><p>'
            . esc_html($message) . '</p></div>';
    }

    /** A count for an axis or a label: 812, 4.3k, 1.2M. */
    public static function short(int $value): string
    {
        foreach ([[1000000, 'M'], [10000, 'k']] as [$size, $suffix]) {
            if ($value >= $size) {
                $text = rtrim(rtrim(number_format($value / $size, 1, '.', ''), '0'), '.');
                return $text . $suffix;
            }
        }
        return number_format_i18n($value);
    }

    /** Rounds an axis top up to 1, 2, or 5 times a power of ten. */
    private static function axisTop(int $max): int
    {
        if ($max <= 4) {
            return 4;
        }
        $power = 10 ** (int) floor(log10($max));
        foreach ([1, 2, 5, 10] as $step) {
            $candidate = $step * $power;
            if ($candidate >= $max) {
                return (int) $candidate;
            }
        }
        return $max;
    }

    /**
     * A trend over time, drawn as inline SVG. No chart library and no canvas,
     * so it renders without JavaScript and cannot be blocked by a CSP.
     *
     * The plot box stretches to the card width while the stroke stays 2px, and
     * the axis labels are HTML, so a phone gets the full-width shape without
     * shrinking text to a smudge.
     *
     * @param list<string> $labels one short label per point, in order
     * @param list<array{label:string,values:list<int>,tone?:string}> $series
     *        tone: accent|ok|warn|bad|muted|info
     */
    public static function areaChart(array $labels, array $series, string $empty = 'Nothing recorded in this window.'): void
    {
        $count = count($labels);
        $max = 0;
        foreach ($series as $line) {
            foreach ((array) $line['values'] as $value) {
                $max = max($max, (int) $value);
            }
        }
        if ($count < 2) {
            echo '<p class="sg-empty">' . esc_html($empty) . '</p>';
            return;
        }

        $top = self::axisTop($max);
        $mid = (int) ceil($top / 2);
        $width = 600;
        $height = 120;
        $base = $height - 2;
        $plot = $base - 4;
        $at = static fn (float $fraction): float => round($fraction, 2);
        $y = static fn (int $value): float => $at($base - ($value / max(1, $top)) * $plot);

        echo '<figure class="sg-chart">';

        echo '<div class="sg-legend">';
        foreach ($series as $line) {
            echo '<span class="sg-legend-item"><i class="sg-swatch sg-tone-' . esc_attr($line['tone'] ?? 'accent')
                . '"></i>' . esc_html($line['label']) . '</span>';
        }
        echo '</div>';

        // With no data the scale is arbitrary, so only the zero line is labelled;
        // the chart says why in the middle instead of implying a range.
        $scale = $max === 0
            ? ['', '', '0']
            : [self::short($top), self::short($mid), '0'];

        echo '<div class="sg-plot">';
        echo '<div class="sg-yaxis" aria-hidden="true"><span>' . esc_html($scale[0]) . '</span><span>'
            . esc_html($scale[1]) . '</span><span>' . esc_html($scale[2]) . '</span></div>';
        echo '<div class="sg-plot-main">';
        echo '<svg class="sg-chart-svg" viewBox="0 0 ' . esc_attr((string) $width) . ' '
            . esc_attr((string) $height) . '" preserveAspectRatio="none" role="img"'
            . ' aria-label="' . esc_attr(implode(' and ', array_map(
                static fn (array $line): string => $line['label'],
                $series
            )) . ' per day, last ' . $count . ' days') . '">';

        foreach ([$top, $mid, 0] as $grid) {
            echo '<line class="sg-gridline" x1="0" y1="' . esc_attr((string) $y($grid)) . '" x2="'
                . esc_attr((string) $width) . '" y2="' . esc_attr((string) $y($grid))
                . '" vector-effect="non-scaling-stroke"></line>';
        }

        foreach ($series as $line) {
            $values = array_values(array_map('intval', (array) $line['values']));
            $values = array_slice(array_pad($values, $count, 0), 0, $count);
            $points = [];
            foreach ($values as $i => $value) {
                $x = $at($i / ($count - 1) * $width);
                $points[] = $x . ',' . $y($value);
            }
            $tone = (string) ($line['tone'] ?? 'accent');
            $path = implode(' L', $points);
            if ($tone === 'accent') {
                echo '<path class="sg-area sg-tone-' . esc_attr($tone) . '" d="M'
                    . esc_attr((string) $at(0)) . ',' . esc_attr((string) $base) . ' L' . esc_attr($path)
                    . ' L' . esc_attr((string) $at((float) $width)) . ',' . esc_attr((string) $base)
                    . ' Z"></path>';
            }
            echo '<path class="sg-chart-line sg-tone-' . esc_attr($tone) . '" d="M' . esc_attr($path)
                . '" vector-effect="non-scaling-stroke"></path>';
        }
        if ($max === 0) {
            echo '<span class="sg-chart-empty">' . esc_html($empty) . '</span>';
        }
        echo '</svg>';

        // Seven labels at most: every step-th day, plus today. When today would
        // sit too close to the previous label, that one is dropped instead.
        $step = max(1, (int) ceil($count / 7));
        $indices = [];
        for ($i = 0; $i < $count - 1; $i += $step) {
            $indices[] = $i;
        }
        if ($indices === [] || end($indices) !== $count - 1) {
            if ($indices !== [] && ($count - 1) - end($indices) < $step) {
                array_pop($indices);
            }
            $indices[] = $count - 1;
        }

        echo '<div class="sg-xaxis" aria-hidden="true">';
        foreach ($indices as $i) {
            $position = round($i / ($count - 1) * 100, 2);
            $edge = $i === 0 ? ' start' : ($i === $count - 1 ? ' end' : '');
            echo '<span class="sg-xlabel' . esc_attr($edge) . '" style="left:' . esc_attr((string) $position) . '%">'
                . esc_html($labels[$i]) . '</span>';
        }
        echo '</div></div></div></figure>';
    }

    /**
     * A ranked list drawn as horizontal bars. A div rather than SVG: the labels
     * stay at text size on a phone and truncate with an ellipsis instead of
     * running under the bar.
     *
     * @param list<array{label:string,value:int,title?:string}> $items
     */
    public static function barList(array $items, string $empty = 'Nothing recorded yet.'): void
    {
        if (!$items) {
            echo '<p class="sg-empty">' . esc_html($empty) . '</p>';
            return;
        }
        $max = max(1, ...array_map(static fn (array $item): int => (int) $item['value'], $items));
        echo '<div class="sg-bars">';
        foreach ($items as $item) {
            $value = (int) $item['value'];
            $width = $value > 0 ? max(2, round($value / $max * 100, 1)) : 0;
            echo '<div class="sg-bar">';
            echo '<span class="sg-bar-label" title="' . esc_attr((string) ($item['title'] ?? $item['label'])) . '">'
                . esc_html($item['label']) . '</span>';
            echo '<span class="sg-bar-track"><span class="sg-bar-fill" style="width:'
                . esc_attr((string) $width) . '%"></span></span>';
            echo '<span class="sg-bar-value">' . esc_html(number_format_i18n($value)) . '</span>';
            echo '</div>';
        }
        echo '</div>';
    }

    /**
     * A 100% stacked bar plus its legend: the quick read on any breakdown.
     *
     * @param list<array{label:string,value:int,tone?:string}> $segments
     */
    public static function splitBar(array $segments, string $empty = 'Nothing recorded yet.'): void
    {
        $total = 0;
        foreach ($segments as $segment) {
            $total += max(0, (int) $segment['value']);
        }
        if ($total === 0) {
            echo '<p class="sg-empty">' . esc_html($empty) . '</p>';
            return;
        }

        echo '<div class="sg-split" role="img" aria-label="' . esc_attr(implode(', ', array_map(
            static fn (array $segment): string => $segment['label'] . ' ' . $segment['value'],
            $segments
        ))) . '">';
        foreach ($segments as $segment) {
            $value = max(0, (int) $segment['value']);
            if ($value === 0) {
                continue;
            }
            $percent = round($value / $total * 100, 1);
            echo '<span class="sg-split-seg sg-tone-' . esc_attr($segment['tone'] ?? 'accent')
                . '" style="width:' . esc_attr((string) $percent) . '%" title="'
                . esc_attr($segment['label'] . ': ' . number_format_i18n($value)) . '"></span>';
        }
        echo '</div>';

        echo '<ul class="sg-legend-list">';
        foreach ($segments as $segment) {
            $value = max(0, (int) $segment['value']);
            if ($value === 0) {
                continue;
            }
            echo '<li><i class="sg-swatch sg-tone-' . esc_attr($segment['tone'] ?? 'accent') . '"></i>'
                . '<span>' . esc_html($segment['label']) . '</span>'
                . '<b>' . esc_html(number_format_i18n($value)) . '</b>'
                . '<em>' . esc_html(round($value / $total * 100, 1) . '%') . '</em></li>';
        }
        echo '</ul>';
    }

    public static function formOpen(string $action, string $nonceAction): void
    {
        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
        wp_nonce_field($nonceAction);
        echo '<input type="hidden" name="action" value="' . esc_attr($action) . '">';
    }

    public static function formClose(string $label = 'Save'): void
    {
        submit_button($label, 'primary', 'submit', false);
        echo '</form>';
    }

    /** Collapsed by default: everything an owner asks before trusting the tool. */
    public static function faq(): void
    {
        $items = [
            'What does SiteGuard actually do?' =>
                'It counts requests and page views, applies per-client request limits, records incidents, '
                . 'and can block a client temporarily. Analytics is best-effort and never decides access.',
            'Can a rule lock me out?' =>
                'Administrators bypass every rule. Blocks expire, and the ladder ends at a ceiling, so no block '
                . 'is permanent. The emergency stop below halts enforcement at once; defining SITEGUARD_DISABLED '
                . 'in wp-config.php does the same before the plugin even loads.',
            'Why do some request types say unavailable?' =>
                'A page served from a cache, or a file served directly by the web server, never reaches '
                . 'WordPress. No plugin can rate-limit what it never sees, so the matrix says so instead of pretending.',
            'Where is the data kept?' =>
                'In this site\'s own WordPress tables. The visitor\'s address, user agent, and browser signals are '
                . 'stored there so the Visitors screen can identify a row; Settings can switch address storage to a '
                . 'keyed hash or off. Retention deletes old rows on a schedule, and exports are generated on demand '
                . 'rather than stored. Nothing leaves the site: the plugin has no connection to any model or '
                . 'analytics service, so a JSON bundle only goes where you send it.',
            'Do I need a cookie banner?' =>
                'The plugin uses a first-party visitor identifier, not a cross-site advertising cookie, and the '
                . 'consent setting can require an explicit choice before collection. Whether you still need a '
                . 'banner depends on your jurisdiction; treat this as engineering, not legal advice.',
            'How do I undo a block?' =>
                'Open Security and press Lift next to the client. Blocks are temporary in any case, and the '
                . 'subject is shown with its rule and remaining time so you can see what triggered it.',
            'What does observe-only change?' =>
                'It counts and records everything but never denies a request. The overview shows a warning while '
                . 'it is active, because it looks like protection without being protection.',
            'How should I read the coverage matrix?' =>
                'Verified means the hook is exercised in this install. Partial means some endpoints of that type '
                . 'are deliberately exempt. Unavailable means WordPress is not reached. Untested means the hook '
                . 'exists but this installation has not exercised it yet.',
        ];

        self::openSection('faq');
        self::sectionTitle('FAQ', 'The questions this tool raises most often, answered in place.');
        echo '<div class="sg-faq">';
        foreach ($items as $question => $answer) {
            echo '<details><summary>' . esc_html($question) . '</summary>';
            echo '<p>' . esc_html($answer) . '</p></details>';
        }
        echo '</div>';
        self::closeSection();
    }
}
