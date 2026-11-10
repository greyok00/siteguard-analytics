<?php
declare(strict_types=1);

namespace SiteGuard\Core\Waf;

use SiteGuard\Core\Clock;
use SiteGuard\Core\Decision;
use SiteGuard\Core\Policy;
use SiteGuard\Core\RequestContext;
use SiteGuard\Core\Subjects;
use SiteGuard\Core\Profile\Fingerprint;
use SiteGuard\Core\Profile\Watchlist as WatchlistLogic;
use SiteGuard\Core\Store\Blocks;
use SiteGuard\Core\Store\Incidents;
use SiteGuard\Core\Store\People;
use SiteGuard\Core\Store\Watchlist;

/**
 * Content-level attack gate: the SECOND detection stage of the pipeline, run
 * by Guard::decide() before the Enforcer. It scores Inspector hits against the
 * configured mode and returns the SAME Decision vocabulary the rest of the
 * plugin uses, so Blocks, Incidents, the ladder and the deny surfaces are all
 * shared. This is the only WAF class that touches storage.
 *
 * Never-regress laws: verified crawlers skip; a scanner user agent alone is
 * never scored (it needs a probe-path partner hit); anomaly hits are
 * count-only and can never satisfy a threshold on their own; only ip/account
 * subjects can be blocked (a forged visitor id can never buy a block); a
 * signed-in non-admin is observed, never denied; observe mode records instead
 * of denying; blocks always expire via the shared ladder.
 */
final class Gate
{
    private const BALANCED_MAX_SEVERITY = 4;
    private const BALANCED_SCORE = 6;
    private const STRICT_MAX_SEVERITY = 3;
    private const STRICT_SCORE = 5;

    /** One recorded incident per subject per this window keeps a scanner that hammers the site from flooding the incidents table. */
    private const RECORD_THROTTLE = 300;

    private const SEVERITY_NAMES = [1 => 'low', 2 => 'low', 3 => 'medium', 4 => 'high', 5 => 'critical'];

    public function __construct(
        private string $mode,
        private Policy $policy,
        private Incidents $incidents,
        private Blocks $blocks,
        private Clock $clock,
        private People $profiles,
        private bool $deviceHints = true,
        private ?Watchlist $watchlist = null
    ) {
    }

    /**
     * @param array{body?:string|array<string,mixed>,headers?:array<string,string>} $extra
     */
    public function check(RequestContext $ctx, array $extra = []): Decision
    {
        if ($this->mode === 'off' || !$this->policy->enabled()) {
            return Decision::allow(['skipped' => 'waf_off']);
        }
        if ($ctx->verifiedCrawler) {
            return Decision::allow(['skipped' => 'waf_verified_crawler']);
        }
        // A subject already serving a block (from this gate or from the rate
        // limiter) is denied with the remaining time instead of gaining a
        // fresh block row on every later request.
        $existing = $this->blockableSubject($ctx);
        if ($existing !== '' && !$ctx->isAuthenticated && $this->mode !== 'observe') {
            $active = $this->blocks->active($existing, $this->clock->now());
            if ($active !== null) {
                return $this->reuse($active, $this->clock->now());
            }
        }

        $hits = Inspector::scan([
            'method' => $ctx->method,
            'path' => $ctx->path,
            'query' => $this->queryFields($ctx->query),
            'body' => $extra['body'] ?? [],
            'headers' => $extra['headers'] ?? ['user-agent' => $ctx->userAgent],
        ]);

        // Stored fingerprint evidence: has THIS browser reported hints no real
        // device of its family ships with? The profile was written by the
        // beacon on an earlier pageview, so a first-ever request carries no
        // profile hits yet — enforcement starts with the second visit, which
        // is exactly when a returning automation client matters. The hits
        // score like any content signature; the BLOCK still lands on the
        // network address (blockableSubject below), never the visitor id.
        // The one stored row feeds BOTH armed merges: the device-hints knob
        // and the watchlist knob toggle independently, but they judge the
        // same profile, so the store is consulted at most once per request.
        $profile = ($this->deviceHints
                || ($this->watchlist !== null && $this->policy->watchlistEnforced()))
            && $ctx->visitorId !== ''
            ? $this->profiles->profileFor($ctx->visitorId)
            : [];
        if ($this->deviceHints && $profile !== []) {
            $hits = array_merge($hits, Fingerprint::hits($profile));
        }
        // Owner-saved watchlist matches: separate block on purpose — the
        // device-hints knob and the watchlist knob toggle independently, so a
        // profile that qualifies feeds BOTH merges only when both are armed.
        // Same score path as the built-in hints: the bar below does the
        // denying, the block still lands on the network address.
        if ($this->watchlist !== null && $this->policy->watchlistEnforced() && $profile !== []) {
            $hits = array_merge($hits, WatchlistLogic::hits($profile, $this->watchlist->all()));
        }

        if (!$hits) {
            return Decision::allow();
        }
        if (!Inspector::hasProbeHit($hits)) {
            // A scanner fingerprint without an application probe is not an
            // attack. Drop those hits; if nothing else matched, pass.
            $hits = array_values(array_filter(
                $hits,
                static fn (array $hit): bool => $hit['group'] !== Rules::GROUP_SCANNER
            ));
            if (!$hits) {
                return Decision::allow(['skipped' => 'waf_scanner_ua_only']);
            }
        }

        [$maxSeverity, $score, $rule, $evidence] = $this->score($hits);
        $evidence = $this->withWatchlistEvidence($hits, $evidence);
        $thresholds = $this->mode === 'strict'
            ? [self::STRICT_MAX_SEVERITY, self::STRICT_SCORE]
            : [self::BALANCED_MAX_SEVERITY, self::BALANCED_SCORE];
        $crossed = $maxSeverity >= $thresholds[0] || $score >= $thresholds[1];
        // The thresholds live next to the score: every incident row shows what
        // bar it was judged against at write time, so a later mode change
        // never restates history.
        $evidence['bar_severity'] = $thresholds[0];
        $evidence['bar_score'] = $thresholds[1];

        $subject = $this->blockableSubject($ctx);
        // Signed-in non-admins are never denied by content rules, so checkout
        // and form posts cannot be broken by a bad pattern.
        if ($crossed && $subject !== '' && !$ctx->isAuthenticated && $this->mode !== 'observe') {
            return $this->deny($subject, $rule, $evidence, $maxSeverity, now: $this->clock->now());
        }

        $this->record($subject, $rule, $maxSeverity, $evidence);
        if ($crossed || $this->mode === 'observe') {
            return Decision::observe($rule, $subject !== '' ? 'ip' : 'unattributable', $evidence);
        }
        // Below the bar: allowed, but the fired rules ride along so the
        // self-test can report "detected, below the threshold" instead of
        // guessing from the outside.
        return Decision::allow(['waf' => 'below_threshold'] + $evidence);
    }

    /**
     * @param list<array{rule:string,group:string,severity:int,evidence:string|array<string,mixed>}> $hits
     * @return array{0:int,1:int,2:string,3:array<string,mixed>} maxSeverity, score, worst rule, evidence bundle
     */
    private function score(array $hits): array
    {
        $maxSeverity = 0;
        $probeCount = 0;
        $worst = null;
        $rules = [];
        foreach ($hits as $hit) {
            $rules[] = $hit['rule'];
            if ($hit['group'] === Rules::GROUP_ANOMALY) {
                continue; // count-only: never satisfies a threshold on its own
            }
            $probeCount++;
            if ($hit['severity'] > $maxSeverity) {
                $maxSeverity = $hit['severity'];
                $worst = $hit;
            }
        }
        // The bonus rewards multi-signature requests but is capped so one
        // payload that trips several variants cannot dominate the score.
        $score = $maxSeverity + max(0, min($probeCount - 1, 2));
        $rule = $worst !== null ? (string) $worst['rule'] : 'waf-anomaly';
        $evidence = [
            'rules' => array_slice(array_values(array_unique($rules)), 0, 3),
            'max_severity' => $maxSeverity,
            'score' => $score,
        ];
        return [$maxSeverity, $score, $rule, $evidence];
    }

    /**
     * Evidence-only enrichment, no enforcement change: a watchlist hit's own
     * evidence array (profile name, anchored reasons, entry id) is folded into
     * the bundle so every incident and block names the entry READABLY, the way
     * the design's incident law requires — rule ids alone show `wl-a1b2c3`,
     * which no one can read later. Capped at 3 like the rules list. Every
     * downstream posture (deny, observe, below-threshold) consumes the same
     * bundle, so all three carry the fold; thresholds, score, subject, and
     * deny logic are untouched by construction.
     * @param list<array{rule:string,group:string,severity:int,evidence:string|array<string,mixed>}> $hits
     * @param array<string,mixed> $evidence
     * @return array<string,mixed>
     */
    private function withWatchlistEvidence(array $hits, array $evidence): array
    {
        $fold = [];
        foreach ($hits as $hit) {
            if (!str_starts_with($hit['rule'], 'wl-') || !is_array($hit['evidence'])) {
                continue;
            }
            $entry = $hit['evidence'];
            $fold[] = [
                'profile' => (string) ($entry['profile'] ?? ''),
                'reasons' => array_values(array_filter((array) ($entry['reasons'] ?? []), 'is_string')),
                'id' => (string) ($entry['id'] ?? ''),
            ];
            if (count($fold) === 3) {
                break;
            }
        }
        return $fold === [] ? $evidence : $evidence + ['watchlist' => $fold];
    }

    private function blockableSubject(RequestContext $ctx): string
    {
        if ($ctx->isAuthenticated && $ctx->accountId) {
            return Subjects::account($ctx->accountId);
        }
        if ($ctx->ipSubject !== '') {
            return Subjects::ip($ctx->ipSubject);
        }
        // Telemetry-derived visitor ids can never carry a block: a forged id
        // would otherwise let an attacker ban someone else.
        return '';
    }

    /**
     * Reuses a running block. Stores differ: the SQLite test store keeps Unix
     * seconds, wpdb keeps a UTC datetime string; accept both so Retry-After
     * never collapses to one second.
     * @param array<string,mixed> $active
     */
    private function reuse(array $active, int $now): Decision
    {
        $expires = $active['expires_at'];
        $expiresAt = is_numeric($expires)
            ? (int) $expires
            : (int) strtotime((string) $expires . ' UTC');
        return Decision::block(
            max(1, $expiresAt - $now),
            (string) ($active['rule'] ?: 'active_block'),
            (string) ($active['scope'] ?: 'ip'),
            ['subject' => (string) $active['subject'], 'block_id' => (int) $active['id']]
        );
    }

    private function deny(string $subject, string $rule, array $evidence, int $maxSeverity, int $now): Decision
    {
        $prior = $this->incidents->countFor($subject, $now - 604800);
        $duration = $this->policy->blockDuration($prior + 1);
        $scope = str_starts_with($subject, Subjects::ACCOUNT_PREFIX) ? 'account' : 'ip';
        $blockId = $this->blocks->add(
            $subject,
            $scope,
            'waf_signature',
            $rule,
            $evidence,
            $now,
            $now + $duration
        );
        $this->incidents->record($subject, $rule, self::name($maxSeverity), $evidence, 1, $blockId, $now);
        return Decision::block($duration, $rule, $scope, ['subject' => $subject, 'block_id' => $blockId] + $evidence);
    }

    private function record(string $subject, string $rule, int $maxSeverity, array $evidence): void
    {
        if ($subject === '') {
            return;
        }
        $now = $this->clock->now();
        if ($this->blocks->active($subject, $now) !== null) {
            return;
        }
        if ($this->incidents->countFor($subject, $now - self::RECORD_THROTTLE) > 0) {
            return;
        }
        $this->incidents->record($subject, $rule, self::name(max(1, $maxSeverity)), $evidence, 1, 0, $now);
    }

    private static function name(int $severity): string
    {
        return self::SEVERITY_NAMES[max(1, min(5, $severity))];
    }

    /**
     * @return array<string,mixed> the query string as named fields for scoring
     */
    private function queryFields(string $query): array
    {
        $query = ltrim($query, '?');
        if ($query === '') {
            return [];
        }
        $fields = [];
        parse_str($query, $fields);
        return array_slice($fields, 0, 64, true);
    }
}
