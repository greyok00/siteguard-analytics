<?php
declare(strict_types=1);

namespace SiteGuard\Core;

use SiteGuard\Core\Store\Blocks;
use SiteGuard\Core\Store\Counters;
use SiteGuard\Core\Store\Distinct;
use SiteGuard\Core\Store\Incidents;

/**
 * Deterministic protection. One call answers one request: allow, or deny with
 * a temporary block. Nothing here trusts a browser-reported value — the
 * visitor id only selects which counter to read, and a forged id can at worst
 * throttle the forger.
 *
 * Storage failures fail open and are reported to the caller; denying every
 * request because a DELETE timed out would be worse than the attack.
 */
final class Enforcer
{
    /** Breadth scanning is only meaningful on page and search traffic. */
    private const BREADTH_CLASSES = [Classifier::HTML, Classifier::SEARCH];

    public function __construct(
        private Policy $policy,
        private Counters $counters,
        private Distinct $distinct,
        private Blocks $blocks,
        private Clock $clock,
        private ?Incidents $incidents = null,
        private bool $breadthEnabled = true
    ) {
    }

    public function check(RequestContext $ctx, bool $recordOnly = false): Decision
    {
        if (!$this->policy->enabled()) {
            return Decision::allow();
        }
        if (!in_array($ctx->endpointClass, Classifier::MANAGED, true)) {
            return Decision::allow(['skipped' => 'unmanaged_class']);
        }
        // A crawler verified by reverse DNS plus forward confirmation is never
        // punished for its user agent string. Unverified impostors are not
        // treated differently from any other unidentified client.
        if ($ctx->verifiedCrawler) {
            return Decision::allow(['skipped' => 'verified_crawler']);
        }

        $subject = $this->primarySubject($ctx);
        if ($subject === '') {
            return Decision::allow(['skipped' => 'unattributable']);
        }

        if ($recordOnly) {
            $this->record($ctx, $subject);
            return Decision::allow(['mode' => 'record_only']);
        }

        $now = $this->clock->now();

        $blocked = $this->blocks->active($subject, $now);
        if ($blocked === null && $ctx->visitorId !== '' && !$ctx->isAuthenticated) {
            $blocked = $this->blocks->active(Subjects::visitor($ctx->visitorId), $now);
        }
        if ($blocked !== null) {
            // Stores differ: the SQLite test store keeps Unix seconds, wpdb
            // keeps a UTC datetime string. Accept both, or every Retry-After
            // collapses to 1 second.
            $expires = $blocked['expires_at'];
            $expiresAt = is_numeric($expires)
                ? (int) $expires
                : (int) strtotime((string) $expires . ' UTC');
            $remaining = $expiresAt - $now;
            return Decision::block(
                max(1, $remaining),
                (string) ($blocked['rule'] ?: 'active_block'),
                (string) ($blocked['scope'] ?: 'ip'),
                ['subject' => (string) $blocked['subject'], 'block_id' => (int) $blocked['id']]
            );
        }

        $violation = $this->firstViolation($ctx, $subject, $now);
        if ($violation === null) {
            return Decision::allow();
        }

        if (!$this->policy->enforces()) {
            return Decision::observe($violation['rule'], $violation['scope'], $violation['evidence']);
        }

        return $this->escalate($ctx, $subject, $violation, $now);
    }

    /** Counters are advanced even in observe mode so the dashboard is honest. */
    public function record(RequestContext $ctx, string $subject = ''): void
    {
        $subject = $subject !== '' ? $subject : $this->primarySubject($ctx);
        if ($subject === '') {
            return;
        }
        $now = $this->clock->now();
        $this->applyCounters($ctx, $subject, $now, true);
    }

    private function primarySubject(RequestContext $ctx): string
    {
        if ($ctx->isAuthenticated && $ctx->accountId) {
            return Subjects::account($ctx->accountId);
        }
        if ($ctx->ipSubject !== '') {
            return Subjects::ip($ctx->ipSubject);
        }
        if ($ctx->visitorId !== '') {
            return Subjects::visitor($ctx->visitorId);
        }
        return '';
    }

    /**
     * @return array{rule:string,scope:string,evidence:array<string,mixed>}|null
     */
    private function firstViolation(RequestContext $ctx, string $subject, int $now): ?array
    {
        $rules = $this->policy->rules($ctx->endpointClass, $ctx->isAuthenticated);
        $counts = $this->applyCounters($ctx, $subject, $now, true);

        $worst = null;
        foreach ($counts as $entry) {
            if ($entry['count'] > $entry['limit']) {
                $candidate = [
                    'rule' => 'rate_' . $entry['window'] . 's',
                    'scope' => str_starts_with($subject, Subjects::ACCOUNT_PREFIX) ? 'account' : 'ip',
                    'evidence' => [
                        'class' => $ctx->endpointClass,
                        'window' => $entry['window'],
                        'limit' => $entry['limit'],
                        'count' => $entry['count'],
                        'subject' => $subject,
                    ],
                ];
                if ($worst === null || $entry['window'] < $worst['evidence']['window']) {
                    $worst = $candidate;
                }
            }
        }
        if ($worst !== null) {
            return $worst;
        }

        if ($this->breadthEnabled
            && in_array($ctx->endpointClass, self::BREADTH_CLASSES, true)
            && $this->policy->distinctLimit() > 0
        ) {
            $window = $this->policy->distinctWindow();
            $windowStart = intdiv($now, $window) * $window;
            $hash = substr(hash('sha256', $ctx->path), 0, 16);
            $this->distinct->touch($subject, $hash, $windowStart);
            $seen = $this->distinct->count($subject, $now - $window);
            $limit = $this->policy->distinctLimit();
            if ($seen > $limit) {
                return [
                    'rule' => 'breadth_' . $window . 's',
                    'scope' => str_starts_with($subject, Subjects::ACCOUNT_PREFIX) ? 'account' : 'ip',
                    'evidence' => [
                        'class' => $ctx->endpointClass,
                        'window' => $window,
                        'limit' => $limit,
                        'distinct' => $seen,
                        'subject' => $subject,
                    ],
                ];
            }
        }

        return null;
    }

    /**
     * @return list<array{window:int,limit:int,count:int}>
     */
    private function applyCounters(RequestContext $ctx, string $subject, int $now, bool $count): array
    {
        $out = [];
        foreach ($this->policy->rules($ctx->endpointClass, $ctx->isAuthenticated) as [$window, $limit]) {
            $windowStart = intdiv($now, $window) * $window;
            $ttl = ($windowStart + $window) - $now + 5;
            $key = Subjects::counterKey($ctx->endpointClass, $subject, $window, $windowStart);
            $countNow = $count
                ? $this->counters->hit($key, $ttl)
                : $this->counters->get($key);
            $out[] = ['window' => $window, 'limit' => $limit, 'count' => $countNow];
        }
        return $out;
    }

    /**
     * @param array{rule:string,scope:string,evidence:array<string,mixed>} $violation
     */
    private function escalate(RequestContext $ctx, string $subject, array $violation, int $now): Decision
    {
        // Incidents keep one row per escalation, while the blocks table keeps a
        // single row per subject, so counting blocks can never climb the ladder.
        $prior = $this->incidents !== null
            ? $this->incidents->countFor($subject, $now - 604800)
            : $this->blocks->recentCount($subject, $now - 604800);
        $duration = $this->policy->blockDuration($prior + 1);
        $expiresAt = $now + $duration;

        // A browser-supplied visitor id must never authorise a persistent ban:
        // forging someone else's id would otherwise let an attacker ban them.
        // Unattributable clients get a short quota denial and nothing is stored.
        if (str_starts_with($subject, Subjects::VISITOR_PREFIX)) {
            return Decision::throttle($duration, $violation['rule'], 'visitor', [
                'subject' => $subject,
                'temporary' => true,
            ]);
        }

        $blockScope = str_starts_with($subject, Subjects::ACCOUNT_PREFIX)
            ? 'account'
            : (str_starts_with($subject, Subjects::VISITOR_PREFIX) ? 'visitor' : 'ip');

        $blockId = $this->blocks->add(
            $subject,
            $blockScope,
            $violation['rule'],
            $violation['rule'],
            $violation['evidence'],
            $now,
            $expiresAt
        );

        $severity = $ctx->endpointClass === Classifier::LOGIN ? 'high' : 'medium';
        if ($this->incidents !== null) {
            $this->incidents->record(
                $subject,
                $violation['rule'],
                $severity,
                $violation['evidence'],
                (int) ($violation['evidence']['count'] ?? 0),
                $blockId,
                $now
            );
        }

        return Decision::block(
            $duration,
            $violation['rule'],
            $blockScope,
            ['subject' => $subject, 'block_id' => $blockId, 'escalation' => $prior + 1]
        );
    }
}
