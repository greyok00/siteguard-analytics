<?php
declare(strict_types=1);

namespace SiteGuard\Wp\Admin;

use SiteGuard\Core\Settings;
use SiteGuard\Wp\Caps;
use SiteGuard\Wp\Config;

/**
 * The Settings section: the enforcement profile, request limits, the block
 * ladder, retention windows, address storage, and the trusted proxy list.
 */
final class SettingsPage
{
    public static function section(): void
    {
        if (!Caps::userCan(Caps::MANAGE_SETTINGS)) {
            return;
        }
        $s = Config::settings();

        Views::openSection('settings');
        Views::sectionTitle('Settings', 'Balanced is the default: protection is active, not a learning-only mode.');

        Views::formOpen('siteguard_settings', 'siteguard_settings');

        Views::openCard('Protection');
        echo '<table class="form-table" role="presentation"><tbody>';

        echo '<tr><th scope="row"><label for="sg-profile">Profile</label></th><td>';
        echo '<select name="profile" id="sg-profile">';
        foreach ([
            'balanced' => 'Balanced — active protection at the baseline limits',
            'strict' => 'Strict — same rules, halved thresholds',
            'observe' => 'Observe only — count and record, never deny',
        ] as $value => $label) {
            echo '<option value="' . esc_attr($value) . '"' . selected($s['profile'], $value, false) . '>'
                . esc_html($label) . '</option>';
        }
        echo '</select><p class="description">Strict multiplies every limit by the strict factor below. Observe is an explicit opt-in and is shown as a warning on the overview.</p></td></tr>';

        echo '<tr><th scope="row">Enforcement</th><td>';
        echo '<input type="hidden" name="enabled" value="0">';
        echo '<label><input type="checkbox" name="enabled" value="1"' . checked((bool) $s['enabled'], true, false) . '> Apply rules to visitor requests</label>';
        echo '<p class="description">Turning this off keeps collection and history running but never denies a request.</p></td></tr>';

        echo '<tr><th scope="row">Collection</th><td>';
        echo '<input type="hidden" name="collect" value="0">';
        echo '<label><input type="checkbox" name="collect" value="1"' . checked((bool) $s['collect'], true, false) . '> Load the first-party collector on the front end</label>';
        echo '</td></tr>';

        echo '<tr><th scope="row"><label for="sg-consent">Consent</label></th><td>';
        echo '<select name="consent_mode" id="sg-consent">';
        foreach ([
            'none' => 'Collect without a prompt',
            'optional' => 'Only after consent; honour Do Not Track',
            'required' => 'Only after consent; the gap is reported',
        ] as $value => $label) {
            echo '<option value="' . esc_attr($value) . '"' . selected($s['consent_mode'], $value, false) . '>'
                . esc_html($label) . '</option>';
        }
        echo '</select><p class="description">This plugin cannot know whether consent was obtained on the host page; when a prompt is required, reports state that figures may be incomplete.</p></td></tr>';

        echo '<tr><th scope="row"><label for="sg-ip">Address storage</label></th><td>';
        echo '<select name="ip_storage" id="sg-ip">';
        foreach (['full' => 'Store the address (shows who visited)', 'hashed' => 'Keyed hash only', 'none' => 'Do not store'] as $value => $label) {
            echo '<option value="' . esc_attr($value) . '"' . selected($s['ip_storage'], $value, false) . '>'
                . esc_html($label) . '</option>';
        }
        echo '</select><p class="description">The address is the one the server saw after trusted-proxy handling. Choose Hashed to keep a keyed digest instead, or None to drop it. Existing rows keep whatever they already stored.</p></td></tr>';

        echo '<tr><th scope="row"><label for="sg-proxies">Trusted proxies</label></th><td>';
        echo '<textarea name="trusted_proxies" id="sg-proxies" rows="3" class="large-text code" placeholder="10.0.0.0/8, 172.16.0.0/12">'
            . esc_textarea((string) $s['trusted_proxies']) . '</textarea>';
        echo '<p class="description">Forwarded headers are ignored unless the direct connection comes from one of these ranges. Leave empty on a normal host.</p></td></tr>';

        echo '</tbody></table>';
        Views::closeCard();

        Views::openCard('Limits per request type');
        echo '<p class="sg-lead">Burst, minute, and hour windows are checked independently; exceeding any one denies the request.</p>';
        echo '<div class="sg-table-wrap"><table class="widefat striped sg-table"><thead><tr>';
        echo '<th scope="col">Request type</th><th scope="col">Per 10 s</th><th scope="col">Per minute</th><th scope="col">Per hour</th></tr></thead><tbody>';
        foreach (Settings::DEFAULT_LIMITS as $class => $defaults) {
            $current = $s['limits'][$class] ?? $defaults;
            echo '<tr><th scope="row">' . esc_html($class) . '</th>';
            foreach ([0, 1, 2] as $i) {
                echo '<td><input type="number" min="1" max="1000000" style="width:7em" name="limits['
                    . esc_attr($class) . '][' . esc_attr((string) $i) . ']" value="'
                    . esc_attr((string) ((int) ($current[$i][1] ?? $defaults[$i][1]))) . '"></td>';
            }
            echo '</tr>';
        }
        echo '</tbody></table></div>';
        Views::closeCard();

        Views::openCard('Breadth and escalation');
        echo '<table class="form-table" role="presentation"><tbody>';
        echo '<tr><th scope="row"><label for="sg-dw">Breadth window</label></th><td>';
        echo '<input type="number" min="60" max="604800" name="distinct_window" id="sg-dw" value="' . esc_attr((string) $s['distinct_window']) . '"> seconds';
        echo '<p class="description">Window used to count distinct paths visited by one client.</p></td></tr>';
        echo '<tr><th scope="row"><label for="sg-dl">Distinct path limit</label></th><td>';
        echo '<input type="number" min="0" max="100000" name="distinct_limit" id="sg-dl" value="' . esc_attr((string) $s['distinct_limit']) . '">';
        echo '<p class="description">Deny when one client requests more than this many different pages in the window. 0 disables the rule.</p></td></tr>';
        echo '<tr><th scope="row"><label for="sg-sf">Strict factor</label></th><td>';
        echo '<input type="number" step="0.05" min="0.1" max="1" name="strict_factor" id="sg-sf" value="' . esc_attr((string) $s['strict_factor']) . '">';
        echo '<p class="description">Multiplier applied to limits in the strict profile.</p></td></tr>';
        echo '<tr><th scope="row"><label for="sg-am">Signed-in multiplier</label></th><td>';
        echo '<input type="number" step="0.1" min="1" max="10" name="account_multiplier" id="sg-am" value="' . esc_attr((string) $s['account_multiplier']) . '">';
        echo '<p class="description">Signed-in accounts get this multiple of the anonymous limit, bounded by the shared server budget.</p></td></tr>';
        echo '<tr><th scope="row"><label for="sg-ladder">Block ladder</label></th><td>';
        echo '<input type="text" class="regular-text code" name="block_ladder" id="sg-ladder" value="'
            . esc_attr(implode(',', array_map('intval', (array) $s['block_ladder']))) . '">';
        echo '<p class="description">Comma-separated durations in seconds. The last value is the ceiling; no block is ever permanent.</p></td></tr>';
        echo '</tbody></table>';
        Views::closeCard();

        Views::openCard('Retention');
        echo '<div class="sg-table-wrap"><table class="widefat striped sg-table"><thead><tr><th scope="col">Dataset</th><th scope="col">Days</th></tr></thead><tbody>';
        foreach (['events' => 'Events', 'sessions' => 'Sessions and visitors', 'incidents' => 'Incidents', 'audit' => 'Audit log', 'counters' => 'Rate counters'] as $key => $label) {
            echo '<tr><th scope="row">' . esc_html($label) . '</th><td>';
            echo '<input type="number" min="1" max="3650" name="retention[' . esc_attr($key) . ']" value="'
                . esc_attr((string) ((int) ($s['retention'][$key] ?? 30))) . '">';
            echo '</td></tr>';
        }
        echo '</tbody></table></div>';
        Views::closeCard();

        echo '<p class="sg-actions">';
        Views::formClose('Save settings');
        echo '</p>';

        Views::closeSection();
    }
}
