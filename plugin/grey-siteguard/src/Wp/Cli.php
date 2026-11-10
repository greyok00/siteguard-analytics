<?php
declare(strict_types=1);

namespace SiteGuard\Wp;

/**
 * WP-CLI surface for hosts and recovery. Read-mostly: the only mutations are
 * lifting a block and running retention, both of which are also in the UI.
 */
final class Cli
{
    public static function boot(): void
    {
        \WP_CLI::add_command('siteguard', self::class);
    }

    /**
     * Shows schema, profile, and block counts.
     *
     * ## EXAMPLES
     *     wp siteguard status
     */
    public function status(): void
    {
        $profile = Config::policy()->profile();
        $blocks = Config::blocks()->countActive(time());
        $missing = [];
        foreach (Installer::tables() as $name) {
            if ($GLOBALS['wpdb']->get_var($GLOBALS['wpdb']->prepare('SHOW TABLES LIKE %s', $name)) !== $name) {
                $missing[] = $name;
            }
        }
        \WP_CLI::log('Schema: ' . get_option(Installer::SCHEMA_OPTION, '0'));
        \WP_CLI::log('Profile: ' . $profile);
        $policy = Config::policy();
        \WP_CLI::log('WAF: ' . $policy->wafMode()
            . ' (' . count(\SiteGuard\Core\Waf\Rules::all()) . ' rules, device hints '
            . ($policy->deviceHintsEnforced() ? 'armed' : 'off') . ')');
        \WP_CLI::log('Enforcement: ' . (Config::emergencyOff() ? 'stopped' : 'on'));
        \WP_CLI::log('Active blocks: ' . $blocks);
        \WP_CLI::log('Missing tables: ' . ($missing ? implode(', ', $missing) : 'none'));
    }

    /**
     * Lists active blocks.
     *
     * ## OPTIONS
     * [--format=<format>]
     * : table, json, or csv. Default: table.
     */
    public function blocks($args, $assoc): void
    {
        $format = $assoc['format'] ?? 'table';
        $rows = [];
        foreach (Config::blocks()->listActive(time(), 200, 0) as $block) {
            $rows[] = [
                'subject' => $block['subject'],
                'scope' => $block['scope'],
                'rule' => $block['rule'],
                'expires_at' => $block['expires_at'],
            ];
        }
        \WP_CLI\Utils\format_items($format, $rows, ['subject', 'scope', 'rule', 'expires_at']);
    }

    /**
     * Lifts one block.
     *
     * ## OPTIONS
     * <subject>
     * : The subject shown by `wp siteguard blocks`.
     */
    public function lift($args): void
    {
        $subject = (string) ($args[0] ?? '');
        if ($subject === '') {
            \WP_CLI::error('A subject is required.');
        }
        $ok = Config::blocks()->lift($subject, time());
        \WP_CLI::success($ok ? 'Block lifted.' : 'No active block for that subject.');
    }

    /**
     * Runs retention now instead of waiting for cron.
     */
    public function prune(): void
    {
        Retention::run();
        \WP_CLI::success('Retention run complete.');
    }

    /**
     * Prints the coverage matrix.
     *
     * ## OPTIONS
     * [--format=<format>]
     */
    public function coverage($args, $assoc): void
    {
        $format = $assoc['format'] ?? 'table';
        $table = Installer::tables()['coverage'];
        $rows = (array) $GLOBALS['wpdb']->get_results("SELECT class, status, reason FROM $table ORDER BY class", ARRAY_A);
        \WP_CLI\Utils\format_items($format, $rows, ['class', 'status', 'reason']);
    }
}
