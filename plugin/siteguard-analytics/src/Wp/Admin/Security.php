<?php
declare(strict_types=1);

namespace SiteGuard\Wp\Admin;

use SiteGuard\Core\Ip;
use SiteGuard\Wp\Caps;
use SiteGuard\Wp\Config;
use SiteGuard\Wp\Installer;

/**
 * The Security section: active temporary blocks, recent incident records, and
 * the manual block form.
 */
final class Security
{
    public static function section(): void
    {
        if (!Caps::userCan(Caps::VIEW_SECURITY)) {
            return;
        }

        $now = time();
        $blocks = Config::blocks()->listActive($now, 100, 0);
        $incidents = (new \SiteGuard\Wp\Store\WpdbIncidentStore($GLOBALS['wpdb']))->recent(50, 0);

        Views::openSection('security');
        Views::sectionTitle('Security', 'Temporary blocks and the incidents that caused them.');

        Views::openCard('Active blocks');
        $rows = [];
        foreach ($blocks as $block) {
            $expires = strtotime((string) $block['expires_at'] . ' UTC');
            $rows[] = [
                '<code>' . esc_html((string) $block['subject']) . '</code>',
                esc_html((string) $block['scope']),
                esc_html((string) $block['rule']),
                esc_html($expires ? human_time_diff($now, $expires) : '—'),
                self::liftButton((string) $block['subject']),
            ];
        }
        Views::table(['Subject', 'Scope', 'Rule', 'Expires in', ''], $rows, 'No active blocks.');
        echo '<p class="sg-foot">Blocks expire; the ladder ends at a ceiling. Administrators are never blocked.</p>';
        Views::closeCard();

        if (Caps::userCan(Caps::MANAGE_BLOCKS)) {
            Views::openCard('Block a client manually');
            Views::formOpen('siteguard_block', 'siteguard_block');
            echo '<table class="form-table" role="presentation"><tbody>';
            echo '<tr><th scope="row"><label for="sg-subject">Address or visitor id</label></th>';
            echo '<td><input name="subject" id="sg-subject" class="regular-text" required placeholder="203.0.113.7 or 32-hex visitor id">';
            echo '<p class="description">An IPv4/IPv6 address is normalised automatically. Visitor ids are the first-party identifiers shown on the visitors page.</p></td></tr>';
            echo '<tr><th scope="row"><label for="sg-hours">Duration</label></th><td>';
            echo '<select name="hours" id="sg-hours">';
            foreach ([1 => '1 hour', 6 => '6 hours', 24 => '1 day', 72 => '3 days', 168 => '7 days'] as $hours => $label) {
                echo '<option value="' . esc_attr((string) $hours) . '">' . esc_html($label) . '</option>';
            }
            echo '</select></td></tr>';
            echo '<tr><th scope="row"><label for="sg-reason">Reason</label></th>';
            echo '<td><input name="reason" id="sg-reason" class="regular-text" maxlength="191" placeholder="Shown in the audit log"></td></tr>';
            echo '</tbody></table>';
            Views::formClose('Apply block');
            Views::closeCard();
        }

        Views::openCard('Recent incidents');
        $rows = [];
        foreach ($incidents as $incident) {
            $evidence = json_decode((string) $incident['evidence'], true);
            $detail = '';
            if (is_array($evidence)) {
                $detail = sprintf(
                    '%s · %s window · %s/%s',
                    (string) ($evidence['class'] ?? ''),
                    isset($evidence['window']) ? $evidence['window'] . 's' : '',
                    (string) ($evidence['count'] ?? $evidence['distinct'] ?? ''),
                    (string) ($evidence['limit'] ?? '')
                );
            }
            $rows[] = [
                esc_html(self::when((string) $incident['ts'])),
                '<code>' . esc_html((string) $incident['subject']) . '</code>',
                Views::badge((string) $incident['severity']),
                esc_html((string) $incident['rule']),
                esc_html($detail),
            ];
        }
        Views::table(['When', 'Subject', 'Severity', 'Rule', 'Evidence'], $rows, 'No incidents recorded.');
        Views::closeCard();

        Views::closeSection();
    }

    private static function liftButton(string $subject): string
    {
        if (!Caps::userCan(Caps::MANAGE_BLOCKS)) {
            return '';
        }
        $url = admin_url('admin-post.php');
        $nonce = wp_create_nonce('siteguard_lift');
        return '<form method="post" action="' . esc_url($url) . '" class="sg-inline">'
            . '<input type="hidden" name="action" value="siteguard_lift">'
            . '<input type="hidden" name="_wpnonce" value="' . esc_attr($nonce) . '">'
            . '<input type="hidden" name="subject" value="' . esc_attr($subject) . '">'
            . '<button type="submit" class="button button-small">Lift</button>'
            . '</form>';
    }

    private static function when(string $utc): string
    {
        $ts = strtotime($utc . ' UTC');
        return $ts ? sprintf('%s ago', human_time_diff($ts, time())) : '—';
    }
}
