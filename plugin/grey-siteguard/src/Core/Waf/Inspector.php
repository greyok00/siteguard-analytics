<?php
declare(strict_types=1);

namespace SiteGuard\Core\Waf;

/**
 * Pure request inspection: given the surfaces of a request (method, path, query,
 * body, headers) it returns every corpus rule that matched. No I/O, no storage,
 * no decisions — the same purity law Classifier follows. Evidence carries only
 * the LOCATION that matched (path / query / body:<field> / header:<name>) and a
 * short truncated excerpt, never the raw payload.
 */
final class Inspector
{
    public const HEADER_SCAN_LIMIT = 24;
    // Bounded-deepening laws (guide wave): how deep nested body arrays and
    // JSON payloads are unwrapped, how many fields a request may contribute,
    // and how large a JSON string is trusted for in-place decode. Every cap
    // keeps the inspector pure, finite, and cheap on ordinary traffic.
    public const SCAN_DEPTH = 3;
    public const FIELD_SCAN_LIMIT = 128;
    public const JSON_SCAN_LIMIT = 8192;

    /**
     * @param array{method?:string,path?:string,query?:array<string,mixed>|string,body?:string|array<string,mixed>,headers?:array<string,string>} $request
     * @return list<array{rule:string,group:string,severity:int,evidence:string}>
     */
    public static function scan(array $request): array
    {
        $rules = Rules::all();
        $hits = [];

        $path = (string) ($request['path'] ?? '');
        foreach (self::search($rules, $path, 'path') as $hit) {
            $hits[] = $hit;
        }

        foreach (self::values($request['query'] ?? []) as $key => $value) {
            foreach (self::search($rules, $value, 'query:' . $key) as $hit) {
                $hits[] = $hit;
            }
        }

        foreach (self::values($request['body'] ?? []) as $key => $value) {
            foreach (self::search($rules, $value, 'body:' . $key) as $hit) {
                $hits[] = $hit;
            }
        }

        $headerCount = 0;
        $headerNames = [];
        foreach (($request['headers'] ?? []) as $name => $value) {
            $headerNames[] = strtolower((string) $name);
            if ($headerCount >= self::HEADER_SCAN_LIMIT) {
                continue; // value scanning stays bounded; header NAMES stay cheap to record
            }
            $headerCount++;
            foreach (self::search($rules, (string) $value, 'header:' . (string) $name) as $hit) {
                $hits[] = $hit;
            }
        }

        // Structural header evidence: no regex fired, the NAME itself is the
        // finding. Proxy-fronting spoofed-routing headers, and the
        // content-length/transfer-encoding pair of a desync (request
        // smuggling) attempt. Count-only anomalies by group — Gate may
        // enrich, never block on these alone.
        $present = array_flip($headerNames);
        if (isset($present['x-original-url']) || isset($present['x-rewrite-url'])) {
            $hits[] = self::structural('anomaly-routing-header', 'header:x-original-url|x-rewrite-url');
        }
        if (isset($present['content-length']) && isset($present['transfer-encoding'])) {
            $hits[] = self::structural('anomaly-smuggling-headers', 'header:content-length+transfer-encoding');
        }

        return $hits;
    }

    /**
     * True when any hit came from a group that represents an actual probe of
     * the application (everything except the scanner and anomaly groups). Gate
     * uses this so a scanner UA is only scored alongside a real probe.
     *
     * @param list<array{rule:string,group:string,severity:int,evidence:string}> $hits
     */
    public static function hasProbeHit(array $hits): bool
    {
        foreach ($hits as $hit) {
            $group = $hit['group'];
            if ($group !== Rules::GROUP_SCANNER && $group !== Rules::GROUP_ANOMALY) {
                return true;
            }
        }
        return false;
    }

    /**
     * @return array<string,string> each scalar leaf, flattened to SCAN_DEPTH
     *     with dot notation. Query and body fields are scanned as "key=value"
     *     so key-signature rules (e.g. author=N enumeration) fire on parsed
     *     requests, not just raw query strings. A JSON object/array string
     *     that fits JSON_SCAN_LIMIT is unwrapped in place, so payloads nested
     *     inside encoded bodies are scanned too.
     */
    private static function values(mixed $container): array
    {
        if (is_string($container)) {
            return ['' => $container];
        }
        if (!is_array($container)) {
            return [];
        }
        $out = [];
        self::flatten('', $container, $out, 0);
        return $out;
    }

    private static function flatten(string $prefix, mixed $value, array &$out, int $depth): void
    {
        if (count($out) >= self::FIELD_SCAN_LIMIT) {
            return;
        }
        if (is_array($value)) {
            if ($depth >= self::SCAN_DEPTH) {
                return;
            }
            foreach ($value as $key => $subValue) {
                self::flatten($prefix === '' ? (string) $key : $prefix . '.' . (string) $key, $subValue, $out, $depth + 1);
                if (count($out) >= self::FIELD_SCAN_LIMIT) {
                    return;
                }
            }
            return;
        }
        if (!is_string($value) && !is_numeric($value)) {
            return;
        }
        $value = (string) $value;
        if ($value === '') {
            return;
        }
        $out[$prefix] = $prefix === '' ? $value : $prefix . '=' . $value;
        if ($depth < self::SCAN_DEPTH && ($value[0] === '{' || $value[0] === '[') && strlen($value) <= self::JSON_SCAN_LIMIT) {
            $parsed = json_decode($value, true);
            if (is_array($parsed)) {
                self::flatten($prefix, $parsed, $out, $depth + 1);
            }
        }
    }

    /**
     * @param list<array{rule:string,group:string,severity:int,pattern:string}> $rules
     * @return list<array{rule:string,group:string,severity:int,evidence:string}>
     */
    private static function search(array $rules, string $subject, string $location): array
    {
        if ($subject === '' || strlen($subject) > 65535) {
            return [];
        }
        $out = [];
        foreach ($rules as $rule) {
            foreach (self::candidates($subject) as $candidate) {
                if (@preg_match($rule['pattern'], $candidate) === 1) {
                    $out[] = [
                        'rule' => $rule['rule'],
                        'group' => $rule['group'],
                        'severity' => $rule['severity'],
                        'evidence' => self::excerpt($location, $candidate),
                    ];
                    break;
                }
            }
        }
        return $out;
    }

    /**
     * Subjects a rule may match against: the URL-decode forms plus, for each
     * form that changes under another normalizer, the HTML-entity-decoded
     * text (a bounded two-pass chain, so "&amp;lt;script&amp;gt;" resolves)
     * and the null-byte-stripped text ("UNI%00ON" is how attacks hide from
     * filters that dropped NULs). Bounded: at most six candidates exist, the
     * loop breaks on the first matching variant, and no form is decoded
     * further than pass two.
     *
     * @return list<string>
     */
    private static function candidates(string $subject): array
    {
        $out = self::variants($subject);
        foreach (self::variants($subject) as $base) {
            $decoded = html_entity_decode($base, ENT_QUOTES | ENT_HTML5, 'UTF-8');
            if ($decoded !== $base) {
                $out[] = $decoded;
                $second = html_entity_decode($decoded, ENT_QUOTES | ENT_HTML5, 'UTF-8');
                if ($second !== $decoded) {
                    $out[] = $second;
                }
            }
            $stripped = str_replace(["\0", '%00'], '', $base);
            if ($stripped !== $base && !in_array($stripped, $out, true)) {
                $out[] = $stripped;
            }
        }
        return array_values(array_unique($out));
    }

    /**
     * A structural finding no regex produced: the header NAME carries all the
     * evidence, so the excerpt is the name, never a raw value. Group anomaly
     * keeps it count-only by construction.
     *
     * @return array{rule:string,group:string,severity:int,evidence:string}
     */
    private static function structural(string $rule, string $evidence): array
    {
        return ['rule' => $rule, 'group' => Rules::GROUP_ANOMALY, 'severity' => Rules::SEVERITY_LOW, 'evidence' => $evidence];
    }

    /**
     * The subject itself plus its URL-decoded forms (two passes max), so a
     * payload hidden behind single or double percent-encoding is matched the
     * way the CRS transform pipeline would. A subject with no percent
     * sequence decodes to itself, so ordinary traffic pays nothing and the
     * benign fixtures stay a no-op.
     *
     * @return list<string>
     */
    private static function variants(string $subject): array
    {
        $decoded = rawurldecode($subject);
        if ($decoded === $subject) {
            return [$subject];
        }
        $second = rawurldecode($decoded);
        if ($second === $decoded || $second === $subject) {
            return [$subject, $decoded];
        }
        return [$subject, $decoded, $second];
    }

    private static function excerpt(string $location, string $subject): string
    {
        $clean = str_replace(["\n", "\r", "\t"], ' ', $subject);
        $excerpt = substr($clean, 0, 120);
        if (strlen($clean) > 120) {
            $excerpt .= '…';
        }
        return $location . ' «' . $excerpt . '»';
    }
}
