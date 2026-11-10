<?php
declare(strict_types=1);

namespace SiteGuard\Wp\Admin;

use SiteGuard\Wp\Caps;

/**
 * The plugin's only admin screen. Every section is rendered in place so an
 * owner can see traffic, incidents, coverage, settings, and the FAQ without
 * changing pages; the header nav scrolls to each one.
 */
final class Page
{
    public static function render(): void
    {
        if (!Caps::userCan(Caps::VIEW_ANALYTICS)) {
            wp_die(esc_html('You do not have permission to view this page.'));
        }

        echo '<div class="wrap sg-wrap">';
        Views::pageTitle('Dashboard', 'Traffic, protection, and every control on one page.');
        Menu::maybeNotice();

        Overview::section();
        Visitors::section();
        Profiles::section();
        Security::section();
        Operations::section();
        SettingsPage::section();
        Views::faq();

        echo '</div>';
    }
}
