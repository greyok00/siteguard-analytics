<?php
declare(strict_types=1);

namespace SiteGuard\Core;

/**
 * The outcome of one policy evaluation. `allowed` is the only field the
 * adapter acts on; the rest exists so every denial can be logged with the
 * rule, scope, evidence, and expiry that produced it.
 */
final class Decision
{
    /** @param array<string,mixed> $evidence */
    private function __construct(
        public readonly bool $allowed,
        public readonly string $reason,
        public readonly string $rule,
        public readonly string $scope,
        public readonly int $retryAfter,
        public readonly int $status,
        public readonly array $evidence
    ) {
    }

    /** @param array<string,mixed> $evidence */
    public static function allow(array $evidence = []): self
    {
        return new self(true, 'allow', '', '', 0, 200, $evidence);
    }

    /** @param array<string,mixed> $evidence */
    public static function block(int $retryAfter, string $rule, string $scope, array $evidence = []): self
    {
        return new self(false, 'blocked', $rule, $scope, max(1, $retryAfter), 429, $evidence);
    }

    /** @param array<string,mixed> $evidence */
    public static function throttle(int $retryAfter, string $rule, string $scope, array $evidence = []): self
    {
        return new self(false, 'quota', $rule, $scope, max(1, $retryAfter), 429, $evidence);
    }

    /** @param array<string,mixed> $evidence */
    public static function challenge(int $retryAfter, string $rule, string $scope, array $evidence = []): self
    {
        return new self(false, 'challenge', $rule, $scope, max(1, $retryAfter), 403, $evidence);
    }

    /** Observed but not denied (observe profile). */
    /** @param array<string,mixed> $evidence */
    public static function observe(string $rule, string $scope, array $evidence = []): self
    {
        return new self(true, 'observe', $rule, $scope, 0, 200, $evidence);
    }

    public function denied(): bool
    {
        return !$this->allowed;
    }
}
