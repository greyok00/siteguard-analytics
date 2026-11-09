<?php
declare(strict_types=1);

namespace SiteGuard\Wp\Admin;

use SiteGuard\Wp\Installer;

/**
 * Self-heal check for the collector: POSTs a synthetic probe (the 'probe' flag
 * makes Beacon::ingest() absorb it without storing anything) against both
 * transports and reports what the answers mean. This is the check that names
 * the exact failure hit on hosts that disable anonymous REST access: the
 * tracker script is queued fine, yet every collect POST dies with 403 before
 * the plugin's permission callback runs, so the dashboard never fills up.
 */
final class CollectorProbe
{
    private const CACHE_KEY = 'siteguard_collector_probe';
    private const CACHE_TTL = 3600;

    /**
     * Runs (or replays from the 1-hour cache) the probe against both
     * transports and returns one row per transport.
     * @return list<array{0:string,1:string}> ['label', plain-language verdict] pairs
     */
    public static function report(): array
    {
        if (empty(Config::settings()['collect'])) {
            return [
                ['Collector REST endpoint', 'collection is switched off in SiteGuard settings'],
                ['Collector admin-ajax fallback', 'collection is switched off in SiteGuard settings'],
            ];
        }

        $result = self::probe();
        $checked = (int) ($result['at'] ?? 0);
        $ago = $checked > 0
            ? sprintf('%s ago', human_time_diff($checked, time()))
            : 'never';

        return [
            ['Collector REST endpoint', sprintf('%s (checked %s)', self::interpretRest((int) ($result['rest'] ?? 0)), $ago)],
            ['Collector admin-ajax fallback', sprintf('%s (checked %s)', self::interpretAjax((int) ($result['ajax'] ?? 0)), $ago)],
        ];
    }

    /**
     * The probe itself: both transports, one POST each, cached an hour so the
     * diagnostics screen never adds latency to a page load. A storage fault
     * answers code 0 rather than throwing: the screen must always render.
     * @return array{at:int,rest:int,ajax:int} response codes (0 = unreachable)
     */
    public static function probe(): array
    {
        $cached = get_transient(self::CACHE_KEY);
        if (is_array($cached) && isset($cached['at'], $cached['rest'], $cached['ajax'])) {
            return $cached;
        }

        $body = wp_json_encode(['probe' => 1, 'type' => 'pageview', 'path' => '/']);
        $result = [
            'at' => time(),
            'rest' => self::post((string) rest_url('siteguard/v1/collect'), (string) $body),
            'ajax' => self::post((string) admin_url('admin-ajax.php?action=siteguard_collect'), (string) $body),
        ];
        set_transient(self::CACHE_KEY, $result, self::CACHE_TTL);
        return $result;
    }

    /**
     * Plain words for the REST answer. 204 is the collector's healthy reply.
     * 403/401 is the host's anonymous-REST kill switch firing before our
     * permission callback can even run — the exact failure mode seen in the
     * field — and the admin-ajax fallback row is what rescues the data.
     */
    public static function interpretRest(int $code): string
    {
        if ($code === 204) {
            return 'healthy (204, probes are being received)';
        }
        if ($code === 403 || $code === 401) {
            return 'blocked by the host (HTTP ' . $code . '): anonymous REST access is disabled sitewide, so the tracker falls back to admin-ajax';
        }
        if ($code === 0) {
            return 'unreachable from this server — the request never completed';
        }
        if ($code === 200) {
            return 'answered 200 — unexpected; the collector replies 204';
        }
        return 'unexpected (HTTP ' . $code . ')';
    }

    /**
     * Plain words for the admin-ajax answer. This transport exists so the
     * first row's 403 is survivable; a healthy answer here means collection
     * still works even while REST is shut.
     */
    public static function interpretAjax(int $code): string
    {
        if ($code === 204) {
            return 'healthy (204, the fallback is accepting probes)';
        }
        if ($code === 0) {
            return 'unreachable from this server — collection is likely broken';
        }
        if ($code === 200) {
            return 'answered 200 — unexpected; the collector replies 204';
        }
        return 'unexpected (HTTP ' . $code . ')';
    }

    /** One POST that only wants the status line back. */
    private static function post(string $url, string $body): int
    {
        if (!class_exists(Installer::class) || empty(Config::settings()['collect'])) {
            return 0;
        }
        $response = wp_remote_post($url, [
            'timeout' => 8,
            'headers' => ['Content-Type' => 'application/json'],
            'body' => $body,
        ]);
        if (is_wp_error($response)) {
            return 0;
        }
        return (int) wp_remote_retrieve_response_code($response);
    }
}
