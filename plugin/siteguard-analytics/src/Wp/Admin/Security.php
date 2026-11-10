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
        $settings = Config::settings();
        $policy = Config::policy();

        Views::openSection('security');
        Views::sectionTitle('Security', 'Protection status, temporary blocks, and the incidents that caused them.');

        self::protectionCard($policy, $settings, $now);
        self::selfTestCard($policy);

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
            $rule = (string) $incident['rule'];
            $rows[] = [
                esc_html(self::when((string) $incident['ts'])),
                '<code>' . esc_html((string) $incident['subject']) . '</code>',
                Views::groupChip($rule),
                Views::badge((string) $incident['severity']),
                esc_html($rule),
                esc_html(self::evidenceLine($rule, $incident['evidence'])),
            ];
        }
        Views::table(['When', 'Subject', 'Family', 'Severity', 'Rule', 'Evidence'], $rows, 'No incidents recorded.');
        Views::closeCard();

        Views::closeSection();
    }

    /**
     * The armed-state card: the lamp row answers "am I defended?" before any
     * number, and the stats grid carries the knobs that set the mode.
     */
    private static function protectionCard(\SiteGuard\Core\Policy $policy, array $settings, int $now): void
    {
        Views::openCard('Protection status');
        $mode = $policy->wafMode();
        $emergency = Config::emergencyOff();

        if ($emergency) {
            Views::armRow('bad', 'The emergency stop has halted protection. Rules are not being applied to any request.');
        } elseif ($mode === 'observe') {
            Views::armRow('warn', 'The content gate is watching, not blocking. Every hit is recorded below; flip the mode in Settings when the record looks sane.');
        } elseif ($mode === 'off') {
            Views::armRow('muted', 'Content signatures are switched off. The rate limiter below still runs on its own profile.');
        } else {
            Views::armRow('ok', 'Content signatures are armed: request payloads and stored fingerprint evidence are scored against the rule corpus, and a crossed threshold denies the network address.');
        }

        $ruleCount = count(\SiteGuard\Core\Waf\Rules::all());
        $deviceHints = !empty($settings['waf_device_hints']);
        $hintsWord = !$deviceHints ? 'off'
            : (empty($settings['collect']) ? 'armed (inert: collection is off)' : 'armed');
        $incidentsToday = (new \SiteGuard\Wp\Store\WpdbIncidentStore($GLOBALS['wpdb']))->countSince($now - 86400);
        $activeBlocks = Config::blocks()->countActive($now);

        Views::stats([
            'Content gate' => ucfirst($mode),
            'Rules' => number_format_i18n($ruleCount),
            'Device hints' => $hintsWord,
            'Incidents today' => number_format_i18n($incidentsToday),
            'Active blocks' => number_format_i18n($activeBlocks),
        ]);

        echo '<p class="sg-foot">'
            . esc_html($mode === 'strict'
                ? 'Strict: a medium-severity probe or a score of 5 is denied; everything else rides the rate limiter.'
                : ($mode === 'balanced'
                    ? 'Balanced: a single high-severity probe is denied; medium hits need a score of 6 — usually several signs at once.'
                    : ($mode === 'observe'
                        ? 'Observe: nothing is denied at any threshold; every probe lands in the incident record.'
                        : 'Off: payloads are never inspected or recorded by the content gate.')))
            . '</p>';
        Views::closeCard();
    }

    /**
     * The WAT card: the acceptance test the corpus must pass in this
     * install, rendered like the collector diagnostics — plain words, one
     * badge per row, a one-line stamp on top.
     */
    private static function selfTestCard(\SiteGuard\Core\Policy $policy): void
    {
        Views::openCard('WAF self-test', 'the acceptance test, run live against throwaway storage');
        $report = WafProbe::report();
        $tone = 'muted';
        foreach ($report['rows'] as $row) {
            if (($row['tone'] ?? '') === 'bad') {
                $tone = 'bad';
                break;
            }
            if (($row['tone'] ?? '') === 'warn') {
                $tone = 'warn';
            }
        }
        Views::probeStamp((string) $report['stamp'], $tone);

        $rows = [];
        foreach ($report['rows'] as $row) {
            $rows[] = [
                esc_html((string) $row['label']),
                '<code>' . esc_html((string) $row['expected']) . '</code>',
                Views::badge($row['tone'] === 'ok' ? 'verified' : ($row['tone'] === 'warn' ? 'partial' : 'unavailable')),
                esc_html((string) $row['verdict']),
            ];
        }
        if ($rows) {
            Views::table(['Surface', 'Expected rule', 'Result', 'What that means'], $rows);
        } else {
            echo '<p class="sg-empty">' . esc_html((string) $report['stamp']) . '</p>';
        }
        echo '<p class="sg-foot">The payloads are probes this plugin itself invented, fired at throwaway copies of the '
            . 'gate: nothing reaches your incident or block tables, and nothing is stored but the one-hour cache of this result. '
            . 'Re-runs happen whenever Settings change; the stamp above is when this result was produced.</p>';
        Views::closeCard();
    }

    /**
     * One evidence line for any incident family: WAF rows read as
     * "signs · score (bar)", rate rows keep their class/window/count line.
     */
    private static function evidenceLine(string $rule, string $json): string
    {
        $evidence = json_decode($json, true);
        if (!is_array($evidence)) {
            return '';
        }
        if (isset($evidence['max_severity'])) {
            $score = (string) ($evidence['score'] ?? '?');
            $bar = isset($evidence['bar_score'])
                ? ' (bar ' . $evidence['bar_severity'] . '/' . $evidence['bar_score'] . ')'
                : '';
            return count($evidence['rules'] ?? []) . ' signs · severity ' . (string) $evidence['max_severity']
                . ' · score ' . $score . $bar;
        }
        return sprintf(
            '%s · %s window · %s/%s',
            (string) ($evidence['class'] ?? ''),
            isset($evidence['window']) ? $evidence['window'] . 's' : '',
            (string) ($evidence['count'] ?? $evidence['distinct'] ?? ''),
            (string) ($evidence['limit'] ?? '')
        );
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
