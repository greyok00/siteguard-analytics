<?php
declare(strict_types=1);

namespace SiteGuard\Core;

/**
 * IPv4/IPv6 normalisation, CIDR checks, and trusted-proxy aware client IP
 * resolution. Forwarding headers are ignored unless the direct peer is inside
 * the configured proxy list; a client cannot claim an address by sending one.
 */
final class Ip
{
    /** Normalises an address to its canonical text form, or null if invalid. */
    public static function normalize(string $value): ?string
    {
        $value = trim($value);
        // [::1]:443 and 1.2.3.4:5678 arrive in some server configurations.
        if (preg_match('/^\[([0-9a-f:.]+)\](?::\d+)?$/i', $value, $m)) {
            $value = $m[1];
        } elseif (substr_count($value, ':') === 1 && str_contains($value, '.')) {
            $value = explode(':', $value)[0];
        }
        $packed = @inet_pton($value);
        if ($packed === false) {
            return null;
        }
        $text = inet_ntop($packed);
        return $text === false ? null : $text;
    }

    /**
     * The counter subject for an address. IPv6 collapses to its /64 so a host
     * rotating addresses inside one allocation cannot reset its budgets; IPv4
     * stays whole (/32).
     */
    public static function subject(string $address): string
    {
        $packed = @inet_pton($address);
        if ($packed === false) {
            return 'ip:unknown';
        }
        if (strlen($packed) === 16) {
            return 'ip6:' . substr(bin2hex($packed), 0, 16);
        }
        return 'ip4:' . bin2hex($packed);
    }

    public static function inCidr(string $address, string $cidr): bool
    {
        [$network, $bits] = array_pad(explode('/', trim($cidr), 2), 2, null);
        $networkIp = self::normalize((string) $network);
        $addressIp = self::normalize($address);
        if ($networkIp === null || $addressIp === null) {
            return false;
        }
        $netPacked = inet_pton($networkIp);
        $ipPacked = inet_pton($addressIp);
        if (strlen($netPacked) !== strlen($ipPacked)) {
            return false;
        }
        $max = strlen($netPacked) * 8;
        $bits = $bits === null ? $max : (int) $bits;
        if ($bits < 0 || $bits > $max) {
            return false;
        }
        $whole = intdiv($bits, 8);
        $rest = $bits % 8;
        if (substr($netPacked, 0, $whole) !== substr($ipPacked, 0, $whole)) {
            return false;
        }
        if ($rest === 0) {
            return true;
        }
        $mask = 0xFF << (8 - $rest) & 0xFF;
        return (ord($netPacked[$whole]) & $mask) === (ord($ipPacked[$whole]) & $mask);
    }

    /**
     * Resolves the client address.
     *
     * X-Forwarded-For is parsed right to left, skipping entries that are
     * themselves trusted proxies; the first untrusted hop is the client.
     * Forwarded chains are capped so a 10 KB header cannot buy work.
     */
    public static function client(string $remoteAddr, array $headers, string $trustedProxies): string
    {
        $remote = self::normalize($remoteAddr) ?? '0.0.0.0';
        $trusted = self::cidrs($trustedProxies);
        if (!$trusted || !self::isTrusted($remote, $trusted)) {
            return $remote;
        }

        $chain = [];
        foreach (['x-forwarded-for'] as $header) {
            $raw = '';
            foreach ($headers as $name => $value) {
                if (strtolower((string) $name) === $header) {
                    $raw = is_array($value) ? implode(',', $value) : (string) $value;
                    break;
                }
            }
            if ($raw === '') {
                continue;
            }
            $parts = array_slice(array_map('trim', explode(',', $raw)), 0, 10);
            foreach ($parts as $part) {
                $ip = self::normalize($part);
                if ($ip !== null) {
                    $chain[] = $ip;
                }
            }
        }
        // RFC 7239 Forwarded: for=1.2.3.4;proto=https
        foreach ($headers as $name => $value) {
            if (strtolower((string) $name) !== 'forwarded') {
                continue;
            }
            $raw = is_array($value) ? implode(',', $value) : (string) $value;
            foreach (array_slice(explode(',', $raw), 0, 10) as $entry) {
                if (preg_match('/for=("?)(\[[^\]]+\]|[^;,"]+)\1/i', $entry, $m)) {
                    $ip = self::normalize(trim($m[2], '"'));
                    if ($ip !== null) {
                        $chain[] = $ip;
                    }
                }
            }
        }
        if (!$chain) {
            return $remote;
        }

        for ($i = count($chain) - 1; $i >= 0; $i--) {
            if (!self::isTrusted($chain[$i], $trusted)) {
                return $chain[$i];
            }
        }
        return $chain[0];
    }

    /** @return list<string> */
    public static function cidrs(string $list): array
    {
        $out = [];
        foreach (preg_split('/[\s,]+/', trim($list)) ?: [] as $entry) {
            if ($entry !== '' && (self::normalize(explode('/', $entry)[0]) !== null)) {
                $out[] = $entry;
            }
        }
        return $out;
    }

    /** @param list<string> $trusted */
    public static function isTrusted(string $address, array $trusted): bool
    {
        foreach ($trusted as $cidr) {
            // A bare address means exactly that address.
            if (!str_contains($cidr, '/') && self::normalize($cidr) === $address) {
                return true;
            }
            if (self::inCidr($address, $cidr)) {
                return true;
            }
        }
        return false;
    }
}
