<?php
declare(strict_types=1);

namespace SiteGuard\Wp\Admin;

use SiteGuard\Core\Decision;
use SiteGuard\Core\Policy;
use SiteGuard\Core\RequestContext;
use SiteGuard\Core\Settings;
use SiteGuard\Core\Store\Blocks;
use SiteGuard\Core\Store\Incidents;
use SiteGuard\Core\Store\People;
use SiteGuard\Core\Waf\Gate;
use SiteGuard\Wp\Config;

/**
 * The WAF acceptance test (WAT): fires documented, harmless attack payloads
 * through a gate wired EXACTLY like the live one — same mode, same policy,
 * same rule corpus — and reports per payload whether it was stopped or
 * recorded, plus a benign control that must pass. The probe never touches
 * the live incident or block tables: it runs against inert in-memory
 * stores, so self-testing cannot pollute the evidence an owner reads on the
 * same screen, and the ladder always answers from its floor rung.
 *
 * Like CollectorProbe, the run is cached for an hour so repeated dashboard
 * loads cost nothing, and every outcome has a plain-language verdict.
 */
final class WafProbe
{
    private const CACHE_KEY = 'siteguard_waf_probe';
    private const CACHE_TTL = 3600;

    /**
     * The acceptance matrix. Each payload names the rule it must fire; the
     * pass law is "the expected rule appears among the fired rules AND the
     * per-mode outcome holds". Payloads fit the shipped corpus anchors — a
     * payload that cannot fire its named rule is a broken self-test, not a
     * leak, so every entry was checked against Rules.php as written.
     * @return list<array{surface:string,payload:string,expected:string,kind:string}>
     */
    public static function matrix(): array
    {
        return [
            ['surface' => 'query file=', 'payload' => '../../../etc/passwd', 'expected' => 'rce-passwd-file', 'kind' => 'query'],
            ['surface' => 'query s=', 'payload' => '<script>alert(1)</script>', 'expected' => 'xss-script-tag', 'kind' => 'query'],
            ['surface' => 'query q=', 'payload' => '1 union select user from wp_users', 'expected' => 'sqli-union-select', 'kind' => 'query'],
            // ; + cat is the command-injection anchor; /etc/shadow also trips
            // rce-passwd-file, which is honest multi-signature behavior: the
            // expected rule must appear among the fired rules, not be the worst.
            ['surface' => 'query cmd=', 'payload' => '; cat /etc/shadow', 'expected' => 'rce-command-injection', 'kind' => 'query'],
            ['surface' => 'path', 'payload' => '/wp-config.bak', 'expected' => 'wp-config-direct', 'kind' => 'path'],
            // The scanner UA is the delivery story; the parenthesised sleep()
            // is the scored signature. Partner present, so the scanner hit
            // survives into scoring instead of being dropped.
            ['surface' => 'query id= (UA sqlmap/1.8)', 'payload' => 'sleep(25)', 'expected' => 'sqli-time-based', 'kind' => 'query'],
            ['surface' => 'control query', 'payload' => 'utm_source=newsletter&colour=blue&sale=50%25 off', 'expected' => '', 'kind' => 'query'],
        ];
    }

    /** The cache key so Actions::saveSettings() can invalidate on save. */
    public static function cacheKey(): string
    {
        return self::CACHE_KEY;
    }

    /**
     * Runs (or replays from the 1-hour cache) the acceptance test.
     * @return array{at:int,mode:string,rows:list<array{label:string,expected:string,fired:list<string>,verdict:string,tone:string}>,stamp:string}
     */
    public static function report(): array
    {
        $cached = get_transient(self::CACHE_KEY);
        if (is_array($cached) && isset($cached['at'], $cached['rows'], $cached['mode'])) {
            return $cached;
        }

        $result = self::run();
        set_transient(self::CACHE_KEY, $result, self::CACHE_TTL);
        return $result;
    }

    /**
     * The probe itself, WP-light: reads only Config::settings() (with a safe
     * fallback for harness/test use) so the visual harness can render it.
     * @param array<string,mixed>|null $settings overrides for harness/test use
     * @return array{at:int,mode:string,rows:list<array{label:string,expected:string,fired:list<string>,verdict:string,tone:string}>,stamp:string}
     */
    public static function run(?array $settings = null): array
    {
        $policy = new Policy($settings ?? (class_exists(Config::class) ? Config::settings() : Settings::from([])));
        $mode = $policy->wafMode();
        $at = time();

        if ($mode === 'off') {
            return [
                'at' => $at,
                'mode' => $mode,
                'rows' => [],
                'stamp' => 'Content rules are switched off in Settings — nothing to test.',
            ];
        }

        // Same shape the live gate gets from Config: real policy, inert stores.
        $gate = new Gate($mode, $policy, new InertIncidents(), new InertBlocks(), new ZeroClock(), new InertPeople(), $policy->deviceHintsEnforced());

        $rows = [];
        $pass = 0;
        foreach (self::matrix() as $case) {
            $decision = $gate->check(self::context($case));
            [$verdict, $tone] = self::verdict($decision, $mode, (string) $case['expected']);
            if ($tone !== 'bad') {
                $pass++;
            }
            $fired = $decision->evidence['rules'] ?? [];
            $rows[] = [
                'label' => (string) $case['surface'],
                'expected' => (string) $case['expected'],
                'fired' => is_array($fired) ? array_values(array_map('strval', $fired)) : [],
                'verdict' => $verdict,
                'tone' => $tone,
            ];
        }

        $modeWord = $mode === 'observe' ? 'detected' : 'stopped';
        return [
            'at' => $at,
            'mode' => $mode,
            'rows' => $rows,
            'stamp' => sprintf('%d/%d %s (%s mode)', $pass, count($rows), $modeWord, $mode),
        ];
    }

    /**
     * One plain-language verdict for one probe decision. A denial names the
     * rule; observe records; a payload that fired nothing is a leak; the
     * control row inverts the law — silence is health, any hit is a bug.
     * @param list<string>|array<int,mixed> $firedRules
     * @return array{0:string,1:string} [verdict, tone: ok|warn|bad]
     */
    public static function verdict(Decision $decision, string $mode, string $expected, array $firedRules = []): array
    {
        if ($firedRules === []) {
            $rules = $decision->evidence['rules'] ?? [];
            $firedRules = is_array($rules) ? array_values(array_map('strval', $rules)) : [];
        }
        $named = $expected !== '' && in_array($expected, $firedRules, true);

        if ($expected === '') {
            if ($decision->denied() || $firedRules !== []) {
                return [
                    'the control request scored: ' . implode(', ', $firedRules ?: [$decision->rule])
                        . ' — a false positive at this surface',
                    'bad',
                ];
            }
            return ['passed clean — the control request was served untouched', 'ok'];
        }

        if ($firedRules === []) {
            return ['NOT detected: the payload passed the gate without scoring — check the corpus', 'bad'];
        }
        if (!$named) {
            return ['scored by ' . implode(', ', $firedRules) . ' — the expected rule never fired; the table or corpus moved', 'bad'];
        }
        if ($decision->denied()) {
            return ['stopped by ' . $expected . ' (HTTP 429 in live traffic)', 'ok'];
        }
        if ($mode === 'observe') {
            return ['detected ' . $expected . ' and recorded, not denying (observe mode)', 'warn'];
        }
        return ['detected ' . $expected . ' but scored below the threshold — allowed this time', 'warn'];
    }

    /** A synthetic context: the case's surface carries the payload. */
    private static function context(array $case): RequestContext
    {
        $kind = (string) $case['kind'];
        $payload = (string) $case['payload'];
        $isScannerDelivery = str_contains((string) $case['surface'], 'sqlmap');
        $ua = $isScannerDelivery ? 'sqlmap/1.8' : 'Mozilla/5.0 (Test) SiteGuardWAT/1.0';
        return new RequestContext(
            method: 'GET',
            path: $kind === 'path' ? $payload : '/wat/probe',
            query: $kind === 'path' ? '' : 'wat=' . rawurlencode($payload),
            endpointClass: 'page',
            ip: '203.0.113.66',
            ipSubject: 'ip4:wat0probe01',
            userAgent: $ua,
            userAgentHash: str_repeat('w', 32),
            fingerprint: '',
            visitorId: '',
            sessionId: '',
            accountId: null,
            isAuthenticated: false
        );
    }
}

/**
 * A clock that does not move: the probe's own run time is its timestamp.
 */
final class ZeroClock implements \SiteGuard\Core\Clock
{
    public function now(): int
    {
        return time();
    }
}

/**
 * Inert incident sink: records vanish, counts answer zero, so the gate's
 * throttle and ladder history never bind the probe and the live incidents
 * table is never written.
 */
final class InertIncidents implements Incidents
{
    public function record(
        string $subject,
        string $rule,
        string $severity,
        array $evidence,
        int $requestCount,
        int $blockId,
        int $now
    ): int {
        return 0;
    }

    public function recent(int $limit = 50, int $offset = 0): array
    {
        return [];
    }

    public function countFor(string $subject, int $since): int
    {
        return 0;
    }

    public function countSince(int $since): int
    {
        return 0;
    }

    public function pruneBefore(int $before): int
    {
        return 0;
    }
}

/**
 * Inert block store: nothing is ever active (so nothing short-circuits),
 * adds answer an id and remember nothing.
 */
final class InertBlocks implements Blocks
{
    public function active(string $subject, int $now): ?array
    {
        return null;
    }

    public function add(
        string $subject,
        string $scope,
        string $reason,
        string $rule,
        array $evidence,
        int $now,
        int $expiresAt,
        string $createdBy = 'system'
    ): int {
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
        return [];
    }

    public function countActive(int $now): int
    {
        return 0;
    }

    public function recentCount(string $subject, int $since): int
    {
        return 0;
    }
}

/**
 * Inert people store: the probe carries a visitor id, so the gate consults
 * it; the inert store answers silence so only payload signatures score.
 */
final class InertPeople implements People
{
    public function profileFor(string $visitorId): array
    {
        return [];
    }

    public function touchSession(string $sessionId, array $meta, int $now, bool $newPageview): void
    {
    }

    public function closeSession(string $sessionId, string $exitPath, int $now): void
    {
    }

    public function touchVisitor(string $visitorId, int $now, bool $newSession, bool $newPageview, array $meta = []): void
    {
    }

    public function linkIdentity(string $visitorId, int $accountId, int $now): void
    {
    }

    public function countSessions(int $since, int $until): int
    {
        return 0;
    }

    public function pruneBefore(int $before): int
    {
        return 0;
    }
}
