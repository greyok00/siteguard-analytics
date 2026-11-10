<?php
declare(strict_types=1);

namespace SiteGuard\Wp;

use SiteGuard\Core\Crypto;
use SiteGuard\Core\Ip;
use SiteGuard\Wp\Store\WpdbEventStore;
use SiteGuard\Wp\Store\WpdbPeopleStore;

/**
 * The collector endpoint.
 *
 * Everything a browser sends is treated as untrusted input: ids must match the
 * documented shape, strings are length capped, the event type is a whitelist,
 * and a per-minute dedupe key is enforced by a unique index so a scripted
 * flood cannot grow the events table. Nothing here influences enforcement.
 */
final class Beacon
{
    private const TYPES = ['pageview', 'leave'];

    /**
     * Browser signals accepted from the tracker. Every value is a short string;
     * the list is the whitelist, so a new field is invisible until it is added
     * here. The set is the usual public fingerprinting surface: what the browser
     * volunteers to any page, plus canvas, WebGL, and audio hashes computed by
     * the tracker and sent as opaque hex strings.
     */
    private const SIGNALS = [
        'lang', 'languages', 'tz', 'tz_offset', 'screen', 'viewport', 'dpr',
        'depth', 'touch', 'cores', 'mem', 'platform', 'ua_brands', 'ua_platform',
        'ua_mobile', 'ua_model', 'ua_arch', 'webgl_vendor', 'webgl_renderer',
        'canvas', 'audio',
    ];

    private const PROFILE_MAX = 4000;

    public static function boot(): void
    {
        add_action('rest_api_init', [self::class, 'routes']);
        // The admin-ajax twin of the REST route: some hosts block anonymous
        // REST access site-wide before any permission callback runs, so the
        // tracker falls back to this transport when the REST path fails.
        add_action('wp_ajax_siteguard_collect', [self::class, 'ajax']);
        add_action('wp_ajax_nositeguard_collect', [self::class, 'ajax']);
    }

    public static function routes(): void
    {
        register_rest_route('siteguard/v1', '/collect', [
            'methods' => 'POST',
            'callback' => [self::class, 'collect'],
            'permission_callback' => '__return_true',
            'args' => [],
        ]);
    }

    /** @return \WP_REST_Response */
    public static function collect(\WP_REST_Request $request)
    {
        $response = new \WP_REST_Response(null, 204);
        $response->header('Cache-Control', 'no-store, no-cache, must-revalidate');

        $data = $request->get_json_params();
        if (!is_array($data)) {
            $raw = $request->get_body();
            $decoded = json_decode((string) $raw, true);
            $data = is_array($decoded) ? $decoded : [];
        }
        self::ingest(is_array($data) ? $data : []);
        return $response;
    }

    /**
     * The admin-ajax transport. Answers 204 like the REST route in every case:
     * validation failures stay silent so a broken payload cannot turn into a
     * javascript console error on the visitor's page.
     */
    public static function ajax(): void
    {
        nocache_headers();
        status_header(204);
        $raw = (string) @file_get_contents('php://input');
        $decoded = json_decode($raw, true);
        if (is_array($decoded)) {
            self::ingest($decoded);
        }
        exit;
    }

    /**
     * The single ingestion path behind both transports. Every rejection is a
     * quiet no-op: the collector never leaks why it dropped a payload.
     * @param array<string,mixed> $data
     */
    private static function ingest(array $data): void
    {
        $settings = Config::settings();
        if (empty($settings['collect']) || !Installer::ready()) {
            return;
        }

        // The diagnostics self-check sends this flag and expects nothing to be
        // stored; it only needs to prove the request reached the plugin.
        if (isset($data['probe'])) {
            return;
        }

        if (!$data) {
            return;
        }

        $visitor = isset($data['visitor']) && is_string($data['visitor']) ? $data['visitor'] : '';
        $session = isset($data['session']) && is_string($data['session']) ? $data['session'] : '';
        if (!Crypto::isId($visitor) || !Crypto::isId($session)) {
            return;
        }

        $type = isset($data['type']) && is_string($data['type']) ? $data['type'] : '';
        if (!in_array($type, self::TYPES, true)) {
            return;
        }

        $path = self::path($data['path'] ?? '');
        if ($path === '') {
            return;
        }
        $referrer = self::referrer($data['referrer'] ?? '');

        $ctx = RequestFactory::build([
            'visitorId' => $visitor,
            'sessionId' => $session,
            'endpointClass' => \SiteGuard\Core\Classifier::REST,
        ]);
        $accountId = $ctx->accountId ?? 0;
        $uaHash = $ctx->userAgentHash;
        $ipMode = (string) ($settings['ip_storage'] ?? 'full');
        $ipHash = self::ipHash($ctx->ip, $ipMode);
        // The address itself is kept only when the owner chose "full". The
        // keyed hash above is written in every mode except "none".
        $ip = $ipMode === 'full' ? substr($ctx->ip, 0, 45) : '';
        $ua = substr($ctx->userAgent, 0, 400);

        $minute = intdiv(time(), 60);
        $dedupe = substr(hash('sha256', $visitor . '|' . $session . '|' . $type . '|' . $path . '|' . $minute), 0, 40);

        $meta = [];
        $profile = null;
        if ($type === 'pageview' && isset($data['fp']) && is_array($data['fp'])) {
            $signals = self::signals($data['fp']);
            if ($signals) {
                // Stored as JSON so the visitor panel can show every value;
                // the hash stays alongside for grouping identical browsers.
                $profile = self::encodeProfile($signals);
                $meta['fingerprint'] = Config::crypto()->fingerprint($signals);
            }
        }
        if ($ctx->isBotLikely) {
            $meta['automated'] = true;
        }

        $events = new WpdbEventStore($GLOBALS['wpdb']);
        $inserted = $events->insert([
            'ts' => gmdate('Y-m-d H:i:s'),
            'source' => 'browser',
            'type' => $type,
            'visitor' => $visitor,
            'session' => $session,
            'account_id' => $accountId,
            'path' => $path,
            'referrer' => $referrer,
            'ua_hash' => $uaHash,
            'device' => self::device($ctx->userAgent),
            'browser' => self::browser($ctx->userAgent),
            'ip' => $ip,
            'ua' => $ua,
            'profile' => $profile,
            'meta' => $meta ?: null,
            'dedupe' => $dedupe,
            'ip_hash' => $ipHash,
        ]);

        // A duplicate within the same minute is a replay, not a pageview.
        if ($inserted < 1) {
            return;
        }

        $people = new WpdbPeopleStore($GLOBALS['wpdb']);
        $isView = $type === 'pageview';
        $people->touchSession(
            $session,
            [
                'visitor' => $visitor,
                'account_id' => $accountId,
                'landing' => $isView ? $path : '',
                'device' => self::device($ctx->userAgent),
                'browser' => self::browser($ctx->userAgent),
                'ip' => $ip,
                'ua' => $ua,
                'ip_hash' => $ipHash,
            ],
            time(),
            $isView
        );
        $people->touchVisitor($visitor, time(), true, $isView, [
            'ip' => $ip,
            'ua' => $ua,
            'ip_hash' => $ipHash,
            'profile' => $profile,
            'last_path' => $isView ? $path : '',
        ]);
        if ($accountId > 0) {
            $people->linkIdentity($visitor, $accountId, time());
        }
        if (!$isView) {
            $people->closeSession($session, $path, time());
        }
    }

    /**
     * Whitelists and clips the browser's fingerprint payload. Strings only:
     * an object or array from a client is ignored rather than encoded.
     *
     * @param array<string,mixed> $fp
     * @return array<string,string>
     */
    private static function signals(array $fp): array
    {
        $out = [];
        foreach (self::SIGNALS as $name) {
            if (!isset($fp[$name]) || !is_scalar($fp[$name])) {
                continue;
            }
            $value = trim((string) $fp[$name]);
            if ($value === '') {
                continue;
            }
            $out[$name] = substr($value, 0, 160);
        }
        return $out;
    }

    /** @param array<string,string> $signals */
    private static function encodeProfile(array $signals): ?string
    {
        $json = wp_json_encode($signals, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (!is_string($json) || $json === '') {
            return null;
        }
        if (strlen($json) > self::PROFILE_MAX) {
            // Drop the long tail (hashes last) rather than store broken JSON.
            $json = wp_json_encode(array_slice($signals, 0, 12, true), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            if (!is_string($json) || strlen($json) > self::PROFILE_MAX) {
                return null;
            }
        }
        return $json;
    }

    private static function path(mixed $value): string
    {
        if (!is_string($value)) {
            return '';
        }
        $value = preg_replace('/[\x00-\x1F\x7F]/', '', $value) ?? '';
        $value = substr($value, 0, 255);
        if ($value === '' || $value[0] !== '/') {
            return '';
        }
        return $value;
    }

    private static function referrer(mixed $value): string
    {
        if (!is_string($value) || $value === '') {
            return '';
        }
        $value = substr($value, 0, 255);
        $scheme = strtolower((string) wp_parse_url($value, PHP_URL_SCHEME));
        return in_array($scheme, ['http', 'https'], true) ? $value : '';
    }

    private static function ipHash(string $ip, string $mode = 'full'): string
    {
        if ($mode === 'none' || $ip === '') {
            return '';
        }
        if ($mode === 'full') {
            return substr($ip, 0, 40);
        }
        return substr(hash_hmac('sha256', Ip::subject($ip), (string) get_option(Installer::SALT_OPTION, '')), 0, 32);
    }

    private static function device(string $ua): string
    {
        if (preg_match('/mobile|android|iphone|ipod/i', $ua)) {
            return 'mobile';
        }
        if (preg_match('/ipad|tablet/i', $ua)) {
            return 'tablet';
        }
        if (preg_match('/bot|crawl|spider/i', $ua)) {
            return 'bot';
        }
        return 'desktop';
    }

    private static function browser(string $ua): string
    {
        // Order matters: Edge and Opera also claim Chrome, Chrome claims Safari.
        foreach ([
            'edg' => 'Edge',
            'opr' => 'Opera',
            'firefox' => 'Firefox',
            'chrome' => 'Chrome',
            'safari' => 'Safari',
        ] as $needle => $name) {
            if (stripos($ua, $needle) !== false) {
                return $name;
            }
        }
        return 'Other';
    }
}
