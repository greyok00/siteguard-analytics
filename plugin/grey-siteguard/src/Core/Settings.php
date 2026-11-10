<?php
declare(strict_types=1);

namespace SiteGuard\Core;

/**
 * Typed option access with defaults. One option row holds everything the
 * owner can change; a missing or partial row falls back to the defaults here.
 */
final class Settings
{
    public const OPTION = 'siteguard_settings';

    /** Default limits: [window seconds, allowed requests] per endpoint class. */
    public const DEFAULT_LIMITS = [
        'html'     => [[10, 20], [60, 60], [3600, 600]],
        'search'   => [[10, 10], [60, 30], [3600, 200]],
        'feed'     => [[10, 10], [60, 30], [3600, 200]],
        'rest'     => [[10, 30], [60, 120], [3600, 1200]],
        'ajax'     => [[10, 30], [60, 120], [3600, 1200]],
        'api'      => [[10, 20], [60, 60], [3600, 600]],
        'login'    => [[10, 5], [60, 10], [3600, 60]],
        'cart'     => [[10, 20], [60, 60], [3600, 600]],
        'checkout' => [[10, 10], [60, 30], [3600, 300]],
        'download' => [[10, 10], [60, 20], [3600, 100]],
    ];

    public static function defaults(): array
    {
        return [
            'enabled' => true,
            // Balanced is the shipped profile: enforcement on, baseline limits.
            'profile' => 'balanced',
            // WAF mode, separate knob from the enforcement profile so turning
            // the WAF on never flips live rate-limit behaviour. balanced is
            // the shipped default for a new install: the site is defended on
            // day one. An install that already stored a value keeps it, so
            // nobody's observe choice flips silently under them.
            'waf_profile' => 'balanced',
            // Impossible-device-hint enforcement: profiles a browser reported
            // that no real device of its family ships with become denial
            // signatures. The always-block-network-address law still holds.
            'waf_device_hints' => true,
            // Fingerprint watchlist enforcement: entries in the watchlist feed
            // the WAF score. Default-armed but inert until an entry exists and
            // the watchlist store is wired.
            'waf_watchlist' => true,
            'limits' => self::DEFAULT_LIMITS,
            // Distinct-path coverage in a 10-minute window. 0 disables the rule.
            'distinct_window' => 600,
            'distinct_limit' => 150,
            'strict_factor' => 0.5,
            // Requests a signed-in account may make before the same limits apply.
            'account_multiplier' => 2.0,
            // Temporary block ladder, seconds. The last entry is the ceiling.
            'block_ladder' => [300, 900, 3600, 21600, 86400],
            'trusted_proxies' => '',
            'retention' => [
                'events' => 30,
                'sessions' => 90,
                'incidents' => 180,
                'audit' => 365,
                'counters' => 2,
            ],
            // none = collect without asking; optional = only after the host page
            // says yes; required = same, and the dashboard states the gap.
            'consent_mode' => 'none',
            // full stores the address itself (the default, so the dashboard can
            // show who visited); hashed keeps a keyed hash; none stores nothing.
            'ip_storage' => 'full',
            'collect' => true,
        ];
    }

    public static function all(): array
    {
        $stored = get_option(self::OPTION, []);
        return self::from(is_array($stored) ? $stored : []);
    }

    /** Merges any stored array over the defaults; used by non-WordPress adapters. */
    public static function from(array $stored): array
    {
        return self::merge(self::defaults(), $stored);
    }

    public static function get(string $path, mixed $fallback = null): mixed
    {
        $value = self::all();
        foreach (explode('.', $path) as $segment) {
            if (!is_array($value) || !array_key_exists($segment, $value)) {
                return $fallback;
            }
            $value = $value[$segment];
        }
        return $value;
    }

    /**
     * Deep merge that keeps stored scalars and adds missing defaults.
     * Lists (block ladders, limit triples) are replaced whole — merging them
     * index by index would leave stale tail entries from the default ladder.
     */
    private static function merge(array $base, array $override): array
    {
        foreach ($override as $key => $value) {
            $isList = is_array($value) && array_values($value) === $value;
            if (is_array($value) && !$isList && isset($base[$key]) && is_array($base[$key])) {
                $base[$key] = self::merge($base[$key], $value);
            } else {
                $base[$key] = $value;
            }
        }
        return $base;
    }

    /**
     * Validates a submitted settings array and returns [clean, errors].
     * Unknown keys are dropped rather than stored.
     */
    public static function sanitize(array $input, ?array $base = null): array
    {
        $clean = $base ?? self::all();
        $errors = [];

        if (array_key_exists('profile', $input)) {
            $profile = (string) $input['profile'];
            if (!in_array($profile, ['balanced', 'strict', 'observe'], true)) {
                $errors[] = 'profile must be balanced, strict, or observe';
            } else {
                $clean['profile'] = $profile;
            }
        }
        if (array_key_exists('waf_profile', $input)) {
            $wafProfile = (string) $input['waf_profile'];
            if (!in_array($wafProfile, ['off', 'observe', 'balanced', 'strict'], true)) {
                $errors[] = 'waf_profile must be off, observe, balanced, or strict';
            } else {
                $clean['waf_profile'] = $wafProfile;
            }
        }
        if (array_key_exists('waf_device_hints', $input)) {
            $clean['waf_device_hints'] = (bool) $input['waf_device_hints'];
        }
        if (array_key_exists('waf_watchlist', $input)) {
            $clean['waf_watchlist'] = (bool) $input['waf_watchlist'];
        }
        if (array_key_exists('enabled', $input)) {
            $clean['enabled'] = (bool) $input['enabled'];
        }
        if (array_key_exists('collect', $input)) {
            $clean['collect'] = (bool) $input['collect'];
        }
        if (array_key_exists('consent_mode', $input)) {
            $mode = (string) $input['consent_mode'];
            if (!in_array($mode, ['none', 'optional', 'required'], true)) {
                $errors[] = 'consent_mode must be none, optional, or required';
            } else {
                $clean['consent_mode'] = $mode;
            }
        }
        if (array_key_exists('ip_storage', $input)) {
            $mode = (string) $input['ip_storage'];
            if (!in_array($mode, ['hashed', 'full', 'none'], true)) {
                $errors[] = 'ip_storage must be hashed, full, or none';
            } else {
                $clean['ip_storage'] = $mode;
            }
        }
        if (array_key_exists('trusted_proxies', $input)) {
            $clean['trusted_proxies'] = trim((string) $input['trusted_proxies']);
        }

        foreach (['distinct_window', 'distinct_limit'] as $key) {
            if (array_key_exists($key, $input)) {
                $value = (int) $input[$key];
                if ($value < 0 || $value > 86400 * 7) {
                    $errors[] = "$key is out of range";
                } else {
                    $clean[$key] = $value;
                }
            }
        }

        foreach (['strict_factor' => [0.1, 1.0], 'account_multiplier' => [1.0, 10.0]] as $key => [$min, $max]) {
            if (!array_key_exists($key, $input)) {
                continue;
            }
            $value = (float) $input[$key];
            if ($value < $min || $value > $max) {
                $errors[] = "$key is out of range";
            } else {
                $clean[$key] = $value;
            }
        }

        if (array_key_exists('block_ladder', $input)) {
            $raw = is_array($input['block_ladder']) ? $input['block_ladder'] : explode(',', (string) $input['block_ladder']);
            $ladder = [];
            foreach (array_slice($raw, 0, 8) as $entry) {
                $seconds = (int) trim((string) $entry);
                if ($seconds >= 60 && $seconds <= 604800) {
                    $ladder[] = $seconds;
                }
            }
            if (!$ladder) {
                $errors[] = 'block_ladder needs at least one duration between 60 and 604800 seconds';
            } else {
                sort($ladder);
                $clean['block_ladder'] = array_values(array_unique($ladder));
            }
        }

        if (isset($input['retention']) && is_array($input['retention'])) {
            foreach (['events', 'sessions', 'incidents', 'audit', 'counters'] as $key) {
                if (!isset($input['retention'][$key])) {
                    continue;
                }
                $days = (int) $input['retention'][$key];
                if ($days < 1 || $days > 3650) {
                    $errors[] = "retention.$key must be 1-3650 days";
                } else {
                    $clean['retention'][$key] = $days;
                }
            }
        }

        // Limits arrive as class => "burst,minute,hour" triples of integers.
        if (isset($input['limits']) && is_array($input['limits'])) {
            foreach ($input['limits'] as $class => $triple) {
                if (!isset(self::DEFAULT_LIMITS[$class]) || !is_array($triple)) {
                    continue;
                }
                $rules = [];
                foreach ([[10, 0], [60, 1], [3600, 2]] as [$window, $index]) {
                    $value = (int) ($triple[$index] ?? 0);
                    if ($value < 1 || $value > 1000000) {
                        $errors[] = "limit for $class is out of range";
                        $rules = [];
                        break;
                    }
                    $rules[] = [$window, $value];
                }
                if ($rules) {
                    $clean['limits'][$class] = $rules;
                }
            }
        }

        return [$clean, $errors];
    }
}
