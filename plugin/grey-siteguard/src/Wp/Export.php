<?php
declare(strict_types=1);

namespace SiteGuard\Wp;

/**
 * Streaming CSV export.
 *
 * Every cell passes through csvCell() so a value beginning with =, +, -, @,
 * tab, or carriage return is prefixed with an apostrophe. Spreadsheets treat
 * those prefixes as formulas, and an incident note is attacker-influenced
 * text, so this is the difference between a report and a payload.
 */
final class Export
{
    private const TYPES = [
        'events' => ['ts', 'source', 'type', 'visitor', 'session', 'account_id', 'path', 'referrer', 'device', 'browser', 'ip', 'ua', 'profile'],
        'sessions' => ['id', 'visitor', 'account_id', 'started_at', 'last_seen', 'pageviews', 'landing', 'exit_path', 'device', 'browser', 'ip', 'ua'],
        'visitors' => ['id', 'first_seen', 'last_seen', 'sessions', 'pageviews', 'ip', 'ua', 'last_path', 'profile'],
        'incidents' => ['ts', 'subject', 'rule', 'severity', 'request_count', 'block_id', 'resolved_at'],
        'blocks' => ['subject', 'scope', 'rule', 'created_at', 'expires_at', 'created_by', 'lifted_at'],
        'audit' => ['ts', 'actor_id', 'action', 'target', 'details'],
    ];

    /** Row cap per table in the single-file bundle. */
    private const BUNDLE_ROWS = 2000;

    public static function stream(string $type): void
    {
        if (!isset(self::TYPES[$type])) {
            wp_die(esc_html('Unknown export type.'), '', ['response' => 400]);
        }
        $columns = self::TYPES[$type];
        $table = Installer::tables()[$type === 'audit' ? 'audit' : $type];

        nocache_headers();
        header('Content-Type: text/csv; charset=utf-8');
        header('Content-Disposition: attachment; filename="siteguard-' . $type . '-' . gmdate('Ymd-His') . '.csv"');
        header('X-Content-Type-Options: nosniff');

        $out = fopen('php://output', 'w');
        if ($out === false) {
            return;
        }
        fputcsv($out, $columns, ',', '"', '');
        foreach (self::rows($table) as $row) {
            $line = [];
            foreach ($columns as $column) {
                $line[] = self::csvCell((string) ($row[$column] ?? ''));
            }
            fputcsv($out, $line, ',', '"', '');
        }
        // The php://output handle is flushed and closed when the request ends;
        // there is no file on disk to release here.
        exit;
    }

    /**
     * One JSON file holding every table, for analysis outside WordPress.
     * The owner downloads this and hands it to whatever tool they choose;
     * the plugin never transmits it.
     */
    public static function streamBundle(): void
    {
        $tables = Installer::tables();
        $names = [
            'events', 'sessions', 'visitors', 'identities',
            'incidents', 'blocks', 'audit',
        ];

        global $wpdb;
        $data = [];
        $counts = [];
        foreach ($names as $name) {
            $table = $tables[$name];
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin-owned tables; an export must read the live rows, never a cache.
            $counts[$name] = (int) $wpdb->get_var(
                $wpdb->prepare('SELECT COUNT(*) FROM %i', $table)
            );
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin-owned tables; one-shot export read.
            $data[$name] = (array) $wpdb->get_results($wpdb->prepare(
                'SELECT * FROM %i ORDER BY 1 DESC LIMIT %d',
                $table,
                self::BUNDLE_ROWS
            ), ARRAY_A);
        }

        $payload = [
            'generated' => gmdate('c'),
            'site' => home_url('/'),
            'plugin' => 'Grey SiteGuard ' . (defined('SITEGUARD_VERSION') ? SITEGUARD_VERSION : ''),
            'note' => 'Rows are capped at ' . self::BUNDLE_ROWS . ' per table, newest first. "counts" is the full table size.',
            'counts' => $counts,
            'tables' => $data,
        ];
        $json = wp_json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (!is_string($json)) {
            wp_die(esc_html('The export could not be encoded.'), '', ['response' => 500]);
        }

        nocache_headers();
        header('Content-Type: application/json; charset=utf-8');
        header('Content-Disposition: attachment; filename="siteguard-bundle-' . gmdate('Ymd-His') . '.json"');
        header('Content-Length: ' . strlen($json));
        header('X-Content-Type-Options: nosniff');
        echo wp_json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        exit;
    }

    /** @return \Generator<array<string,mixed>> */
    private static function rows(string $table): \Generator
    {
        global $wpdb;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin-owned tables; export pages straight from the live rows.
        $total = (int) $wpdb->get_var(
            $wpdb->prepare('SELECT COUNT(*) FROM %i', $table)
        );
        $pageSize = 500;
        for ($offset = 0; $offset < $total; $offset += $pageSize) {
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- plugin-owned tables; one page of an export stream.
            $rows = $wpdb->get_results($wpdb->prepare(
                'SELECT * FROM %i ORDER BY id DESC LIMIT %d OFFSET %d',
                $table,
                $pageSize,
                $offset
            ), ARRAY_A);
            foreach ((array) $rows as $row) {
                yield $row;
            }
        }
    }

    public static function csvCell(string $value): string
    {
        if ($value === '') {
            return '';
        }
        $first = $value[0];
        if (in_array($first, ['=', '+', '-', '@', "\t", "\r"], true)) {
            return "'" . $value;
        }
        return $value;
    }
}
