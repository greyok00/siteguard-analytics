<?php
declare(strict_types=1);

/**
 * Visual harness: renders the Security section's protection + self-test cards
 * (plus one flagged-visitor sample row) into static HTML with the real CSS.
 *
 *     php dev/tools/render-protection.php           # writes dev/tools/shots/protection.html
 *
 * The shim defines only the WP functions this render path touches; the probe
 * runs against inert stores and Config is seeded with explicit settings, so
 * nothing here reads a live WordPress database.
 */

$root = dirname(__DIR__, 2);
define('ABSPATH', $root . '/');
define('SITEGUARD_DIR', $root . '/plugin/siteguard-analytics/');

// The stores call wpdb's fetch-mode constants UNQUALIFIED from inside the
// SiteGuard\Wp\Store namespace; in real WordPress those resolve to the loaded
// global wpdb constants. In the harness, define the namespaced fallbacks
// before anything loads.
if (!defined('SiteGuard\Wp\Store\ARRAY_A')) {
    define('SiteGuard\Wp\Store\ARRAY_A', 'ARRAY_A');
}
if (!defined('SiteGuard\Wp\Store\ARRAY_N')) {
    define('SiteGuard\Wp\Store\ARRAY_N', 'ARRAY_N');
}
if (!defined('SiteGuard\Wp\Store\OBJECT')) {
    define('SiteGuard\Wp\Store\OBJECT', 'OBJECT');
}

// ---- Boot the real renderer -------------------------------------------------
require SITEGUARD_DIR . 'src/Core/autoload.php';

// ---- WP shim ---------------------------------------------------------------
$i18n = static function (string $s): string {
    return $s;
};
// number_format_i18n
function number_format_i18n(float|int $number): string
{
    return number_format((float) $number);
}
function esc_html(string $text): string
{
    return htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
}
function esc_attr(string $text): string
{
    return htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
}
function esc_url(string $url): string
{
    return htmlspecialchars($url, ENT_QUOTES, 'UTF-8');
}
function human_time_diff(int $from, int $to): string
{
    $d = max(1, abs($to - $from));
    if ($d < 60) {
        return $d . ' secs';
    }
    if ($d < 3600) {
        return (int) ($d / 60) . ' mins';
    }
    if ($d < 86400) {
        return (int) ($d / 3600) . ' hours';
    }
    return (int) ($d / 86400) . ' days';
}
function get_option(string $name, mixed $default = false): mixed
{
    return $GLOBALS['shim_options'][$name] ?? $default;
}
function get_transient(string $name): mixed
{
    return false; // always render a fresh probe run
}
function set_transient(string $name, mixed $value, int $ttl): bool
{
    return true;
}
function delete_transient(string $name): bool
{
    return true;
}
function apply_filters(string $name, mixed $value): mixed
{
    return $value;
}
function add_filter(string $name, callable $cb, int $prio = 10, int $args = 1): bool
{
    return true;
}
function add_action(string $name, callable $cb, int $prio = 10, int $args = 1): bool
{
    return true;
}
function current_user_can(string $cap): bool
{
    return true;
}
function is_user_logged_in(): bool
{
    return true;
}
function get_current_user_id(): int
{
    return 1;
}
function admin_url(string $path = ''): string
{
    return 'https://example.test/wp-admin/' . $path;
}
function wp_create_nonce(string $action): string
{
    return 'shimnonce';
}
function home_url(string $path = ''): string
{
    return 'https://example.test' . $path;
}
function rest_url(string $path = ''): string
{
    return 'https://example.test/wp-json/';
}
function site_url(): string
{
    return 'https://example.test';
}
function wp_safe_redirect(string $url): void
{
}
function submit_button(string $label = 'Save', string $type = 'primary', string $name = 'submit', bool $wrap = true, array $attr = []): void
{
    echo '<p class="wp-admin"><button type="submit" class="button ' . esc_attr($type) . '">' . esc_html($label) . '</button></p>';
}
function checked(mixed $checked, bool $current = true, bool $echo = true): string
{
    $s = ((bool) $checked === $current) ? " checked='checked'" : '';
    if ($echo) {
        echo $s;
    }
    return $s;
}
function selected(mixed $selected, mixed $current = true, bool $echo = true): string
{
    $s = ((string) $selected === (string) $current) ? " selected='selected'" : '';
    if ($echo) {
        echo $s;
    }
    return $s;
}
function wp_parse_url(string $url, int $component = -1): mixed
{
    return $component === -1 ? parse_url($url) : parse_url($url, $component);
}
function wp_json_encode(mixed $data): string
{
    return (string) json_encode($data);
}
function wp_nonce_field(string $action = '-1', string $name = '_wpnonce', bool $referer = true, bool $echo = true): string
{
    $s = '<input type="hidden" id="_wpnonce" name="' . esc_attr($name) . '" value="shimnonce">';
    if ($referer) {
        $s .= '<input type="hidden" name="_wp_http_referer" value="/">';
    }
    if ($echo) {
        echo $s;
    }
    return $s;
}
function wp_nonce_url(string $url, string $action = '-1', string $name = '_wpnonce'): string
{
    return $url;
}
function add_query_arg(...$args): string
{
    return is_array($args[0] ?? null) ? $args[1] : (string) $args[0];
}
function wp_timezone(): DateTimeZone
{
    return new DateTimeZone('UTC');
}
function date_i18n(string $format, ?int $ts = null): string
{
    return gmdate($format, $ts ?? time());
}
function get_date_from_gmt(string $string, string $format = 'Y-m-d H:i:s'): string
{
    return $string;
}
function sanitize_text_field(string $s): string
{
    return trim($s);
}
function wp_unslash(mixed $value): mixed
{
    return $value;
}
function absint(mixed $n): int
{
    return abs((int) $n);
}
function current_time(string $type): string
{
    return gmdate('Y-m-d H:i:s');
}
function get_role(string $role): ?object
{
    return null;
}
function wp_die(string $message = ''): void
{
    fwrite(STDERR, $message . "\n");
    exit(1);
}
function wp_kses(string $string, array $allowed_html = [], array $allowed_protocols = []): string
{
    return $string; // harness: the nav markup is plugin-authored
}
function wp_kses_post(string $string): string
{
    return $string;
}
// --- wpdb shim ---------------------------------------------------------------
class wpdb
{
    public string $prefix = 'wp_';

    /** Canned rows for the Security card so the render exercises populated
     *  incident tables; keyed roughly by the SQL a store is likely to run. */
    public array $shim_rows = [];

    public function prepare(string $sql, ...$args): string
    {
        return $sql;
    }

    public function get_var(string $sql): mixed
    {
        return null;
    }

    public function get_results(string $sql, ?string $mode = null): array
    {
        return $this->shim_rows;
    }

    public function query(string $sql): bool
    {
        return true;
    }
}
$GLOBALS['wpdb'] = new wpdb();

class ShimWafProbeBlocks implements \SiteGuard\Core\Store\Blocks
{
    public function active(string $subject, int $now): ?array
    {
        return null;
    }

    public function add(string $subject, string $scope, string $reason, string $rule, array $evidence, int $now, int $expiresAt, string $createdBy = 'system'): int
    {
        return 0;
    }

    public function lift(string $subject, int $now): bool
    {
        return false;
    }

    public function prune(int $now, int $limit = 200): int
    {
        return 0;
    }

    public function listActive(int $now, int $limit = 100, int $offset = 0): array
    {
        return [
            [
                'subject' => 'ip4:0a3fcafe', 'scope' => 'ip', 'rule' => 'fp-touchless-ios',
                'evidence' => '{"rules":["fp-touchless-ios"],"max_severity":4,"score":4,"bar_severity":4,"bar_score":6}',
                'created_at' => gmdate('Y-m-d H:i:s', time() - 600),
                'expires_at' => gmdate('Y-m-d H:i:s', time() + 2400),
            ],
            [
                'subject' => 'ip4:0a3fcafd', 'scope' => 'ip', 'rule' => 'rate_60s',
                'evidence' => '{"class":"page","window":60,"count":47,"limit":40}',
                'created_at' => gmdate('Y-m-d H:i:s', time() - 1800),
                'expires_at' => gmdate('Y-m-d H:i:s', time() + 900),
            ],
        ];
    }

    public function countActive(int $now): int
    {
        return 2;
    }

    public function recentCount(string $subject, int $since): int
    {
        return 0;
    }
}

class ShimWafProbeIncidents implements \SiteGuard\Core\Store\Incidents
{
    public function record(string $subject, string $rule, string $severity, array $evidence, int $requestCount, int $blockId, int $now): int
    {
        return 0;
    }

    public function recent(int $limit = 50, int $offset = 0): array
    {
        return [
            [
                'ts' => gmdate('Y-m-d H:i:s', time() - 420),
                'subject' => 'ip4:0a3fcafe',
                'rule' => 'fp-touchless-ios',
                'severity' => 'high',
                'evidence' => '{"rules":["fp-touchless-ios"],"max_severity":4,"score":4,"bar_severity":4,"bar_score":6}',
            ],
            [
                'ts' => gmdate('Y-m-d H:i:s', time() - 1900),
                'subject' => 'ip4:0a3fcafd',
                'rule' => 'rate_60s',
                'severity' => 'medium',
                'evidence' => '{"class":"page","window":60,"count":47,"limit":40}',
            ],
        ];
    }

    public function countFor(string $subject, int $since): int
    {
        return 0;
    }

    public function countSince(int $since): int
    {
        return 2;
    }

    public function pruneBefore(int $before): int
    {
        return 0;
    }
}

// ---- Boot the real renderer -------------------------------------------------
require SITEGUARD_DIR . 'src/Core/autoload.php';

// ---- Seed Config with harness state -----------------------------------------
$GLOBALS['shim_options'] = [
    'siteguard_settings' => \SiteGuard\Core\Settings::from([
        'waf_profile' => $argv[1] ?? 'balanced',
        'waf_device_hints' => ($argv[2] ?? '1') === '1',
    ]),
];
$ref = new ReflectionClass(\SiteGuard\Wp\Config::class);
$p = $ref->getProperty('settings');
$p->setValue(null, \SiteGuard\Core\Settings::from($GLOBALS['shim_options']['siteguard_settings']));
// Stores the Security render uses live in Config; point them at the shims.
$set = static function (string $name, object $value) use ($ref) {
    $p = $ref->getProperty($name);
    $p->setValue(null, $value);
};
$set('blocks', new ShimWafProbeBlocks());
$set('incidents', new ShimWafProbeIncidents());

// Security reads incidents through wpdb directly; seed the canned rows there
// so the Recent incidents card renders populated.
$GLOBALS['wpdb']->shim_rows = [
    [
        'id' => 2,
        'ts' => gmdate('Y-m-d H:i:s', time() - 1900),
        'subject' => 'ip4:0a3fcafd',
        'rule' => 'rate_60s',
        'severity' => 'medium',
        'evidence' => '{"class":"page","window":60,"count":47,"limit":40}',
        'request_count' => 47,
        'block_id' => 2,
        'resolved_at' => null,
    ],
    [
        'id' => 1,
        'ts' => gmdate('Y-m-d H:i:s', time() - 420),
        'subject' => 'ip4:0a3fcafe',
        'rule' => 'fp-touchless-ios',
        'severity' => 'high',
        'evidence' => '{"rules":["fp-touchless-ios"],"max_severity":4,"score":4,"bar_severity":4,"bar_score":6}',
        'request_count' => 12,
        'block_id' => 1,
        'resolved_at' => null,
    ],
];

// The CLI/notice paths only read time(); keep the default timezone UTC for
// deterministic stamps.
date_default_timezone_set('UTC');

ob_start();
echo '<!doctype html><html><head><meta charset="utf-8">';
echo '<meta name="viewport" content="width=device-width, initial-scale=1">';
echo '<title>SiteGuard protection render</title>';
// Inlined instead of linked: headless file:// pages refuse cross-directory
// stylesheets, and the screenshot must show the real styling.
echo '<style>' . file_get_contents(SITEGUARD_DIR . 'assets/admin.css') . '</style>';
echo '</head><body style="background:#0e1013;margin:20px;">';
echo '<div class="wrap sg-wrap">';
\SiteGuard\Wp\Admin\Views::pageTitle('Dashboard', 'Traffic, protection, and every control on one page.');
\SiteGuard\Wp\Admin\Security::section();
echo '</div>';
echo '</body></html>';
$html = (string) ob_get_clean();

$out = __DIR__ . '/shots/protection.html';
if (!is_dir(dirname($out))) {
    mkdir(dirname($out), 0777, true);
}
file_put_contents($out, $html);
echo 'wrote ', $out, "\n";
