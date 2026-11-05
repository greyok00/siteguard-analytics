<?php
declare(strict_types=1);

namespace SiteGuard\Core;

/**
 * Identifiers and keyed hashes.
 *
 * Two secrets, both site-scoped:
 *  - $siteSalt keys subject hashes (IP, user agent) and confirmation tokens.
 *  - $fingerprintSalt keys the passive browser-correlation hash and may be
 *    rotated; its version is part of the stored value so old hashes stop
 *    matching instead of silently comparing across rotations.
 *
 * A hashed value is pseudonymous, not anonymous.
 */
final class Crypto
{
    public function __construct(
        private string $siteSalt,
        private string $fingerprintSalt,
        private int $fingerprintVersion = 1
    ) {
    }

    public static function randomSecret(int $bytes = 32): string
    {
        return bin2hex(random_bytes($bytes));
    }

    /** A 128-bit random public identifier, hex encoded (cookie-safe). */
    public static function randomId(): string
    {
        return bin2hex(random_bytes(16));
    }

    public static function isId(string $value): bool
    {
        return (bool) preg_match('/^[a-f0-9]{32}$/', $value);
    }

    public function fingerprint(array $signals): string
    {
        $normalized = [];
        foreach ($signals as $name => $value) {
            $normalized[] = $name . '=' . self::normalizeSignal((string) $value);
        }
        sort($normalized);
        $hash = substr(hash_hmac('sha256', implode('|', $normalized), $this->fingerprintSalt), 0, 32);
        return 'fp' . $this->fingerprintVersion . ':' . $hash;
    }

    /** Lowercase, collapse whitespace, drop the version tails of UAs. */
    public static function normalizeSignal(string $value): string
    {
        $value = strtolower(trim(preg_replace('/\s+/', ' ', $value) ?? ''));
        return substr($value, 0, 180);
    }

    public function subject(string $type, string $value): string
    {
        return $type . ':' . substr(hash_hmac('sha256', $type . "\0" . $value, $this->siteSalt), 0, 32);
    }

    public function sign(string $purpose, string $payload): string
    {
        return hash_hmac('sha256', $purpose . "\0" . $payload, $this->siteSalt);
    }

    public function verify(string $purpose, string $payload, string $signature): bool
    {
        return hash_equals($this->sign($purpose, $payload), $signature);
    }
}
