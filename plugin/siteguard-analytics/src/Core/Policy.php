<?php
declare(strict_types=1);

namespace SiteGuard\Core;

/**
 * Turns the settings into the numbers the enforcer uses. Thresholds are
 * starting points tuned for a PHP/MySQL shared host, not guarantees; the
 * dashboard shows them and they are editable.
 */
final class Policy
{
    public const BALANCED = 'balanced';
    public const STRICT = 'strict';
    public const OBSERVE = 'observe';

    public function __construct(private array $settings)
    {
    }

    public function profile(): string
    {
        $profile = (string) ($this->settings['profile'] ?? self::BALANCED);
        return in_array($profile, [self::BALANCED, self::STRICT, self::OBSERVE], true)
            ? $profile
            : self::BALANCED;
    }

    /** Observe logs decisions but never denies. */
    public function enforces(): bool
    {
        return $this->profile() !== self::OBSERVE;
    }

    public function enabled(): bool
    {
        return (bool) ($this->settings['enabled'] ?? true);
    }

    /**
     * Rules for a class as [windowSeconds, limit] pairs, already scaled for
     * the profile and for a signed-in account.
     *
     * @return list<array{0:int,1:int}>
     */
    public function rules(string $class, bool $authenticated): array
    {
        $limits = $this->settings['limits'] ?? Settings::DEFAULT_LIMITS;
        $rules = $limits[$class] ?? null;
        if (!is_array($rules)) {
            return [];
        }
        $factor = $this->profile() === self::STRICT
            ? max(0.1, (float) ($this->settings['strict_factor'] ?? 0.5))
            : 1.0;
        if ($authenticated) {
            $factor *= max(1.0, (float) ($this->settings['account_multiplier'] ?? 2.0));
        }
        $out = [];
        foreach ($rules as $rule) {
            if (!is_array($rule) || count($rule) < 2) {
                continue;
            }
            $window = (int) $rule[0];
            $limit = (int) $rule[1];
            if ($window > 0 && $limit > 0) {
                $out[] = [$window, max(1, (int) ceil($limit * $factor))];
            }
        }
        return $out;
    }

    public function distinctLimit(): int
    {
        if ($this->profile() === self::OBSERVE) {
            return 0;
        }
        $limit = (int) ($this->settings['distinct_limit'] ?? 0);
        if ($this->profile() === self::STRICT) {
            $limit = (int) ceil($limit * max(0.1, (float) ($this->settings['strict_factor'] ?? 0.5)));
        }
        return max(0, $limit);
    }

    public function distinctWindow(): int
    {
        return max(60, (int) ($this->settings['distinct_window'] ?? 600));
    }

    /**
     * Temporary block length for the nth violation, in seconds. Never
     * permanent: the last rung is the ceiling.
     */
    public function blockDuration(int $violationCount): int
    {
        $ladder = array_values(array_filter(
            array_map('intval', (array) ($this->settings['block_ladder'] ?? [300, 900, 3600, 21600, 86400])),
            static fn (int $s): bool => $s > 0
        ));
        if (!$ladder) {
            $ladder = [300, 900, 3600, 21600, 86400];
        }
        $index = min(max(0, $violationCount - 1), count($ladder) - 1);
        return $ladder[$index];
    }

    public function retentionDays(string $dataset): int
    {
        $retention = $this->settings['retention'] ?? [];
        $days = (int) ($retention[$dataset] ?? 30);
        return max(1, $days);
    }
}
