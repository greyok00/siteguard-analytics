<?php
declare(strict_types=1);

namespace SiteGuard\Tests;

use SiteGuard\Core\Decision;
use SiteGuard\Core\Policy;
use SiteGuard\Core\RequestContext;
use SiteGuard\Core\Settings;
use SiteGuard\Core\Waf\Gate;
use SiteGuard\Wp\Admin\WafProbe;

/**
 * The self-test must be truthful: every matrix payload fires its named rule
 * against the shipped corpus, deny-modes stop all six, observe detects all
 * six, the control stays silent, and the inert stores prove the probe never
 * writes evidence an owner would read.
 */
final class WafProbeTest extends TestCase
{
    public function testEveryMatrixPayloadFiresItsExpectedRule(): void
    {
        // A dry corpus check WITHOUT the gate: each expected rule id must
        // actually exist in Rules::all(), so a future corpus rename breaks
        // the test table loudly instead of reporting false leaks.
        $corpus = array_column(\SiteGuard\Core\Waf\Rules::all(), 'rule');
        foreach (WafProbe::matrix() as $case) {
            if ($case['expected'] === '') {
                continue;
            }
            $this->assertTrue(in_array($case['expected'], $corpus, true),
                'matrix names a rule the corpus does not ship: ' . $case['expected']);
        }
    }

    public function testBalancedStopsAllSixAndPassesTheControl(): void
    {
        $result = WafProbe::run(Settings::from(['waf_profile' => 'balanced']));
        $this->assertSame('balanced', $result['mode']);
        $this->assertCount(7, $result['rows']);
        foreach ($result['rows'] as $i => $row) {
            if ($i === 6) {
                $this->assertSame('ok', $row['tone'], 'the control request must pass clean: ' . $row['verdict']);
                continue;
            }
            $this->assertSame('ok', $row['tone'], 'balanced must stop: ' . $row['label'] . ' — ' . $row['verdict']);
            $this->assertTrue(str_contains($row['verdict'], 'stopped by ' . $row['expected']),
                'the verdict names the rule that fired: ' . $row['verdict']);
        }
        $this->assertSame('7/7 stopped (balanced mode)', $result['stamp'], 'the stamp reads as a plain score — six attacks plus the control.');
    }

    public function testObserveDetectsAllSixWithoutDenying(): void
    {
        $result = WafProbe::run(Settings::from(['waf_profile' => 'observe']));
        foreach ($result['rows'] as $i => $row) {
            if ($i === 6) {
                $this->assertSame('ok', $row['tone']);
                continue;
            }
            $this->assertSame('warn', $row['tone'], 'observe records, never denies: ' . $row['verdict']);
            $this->assertTrue(str_contains($row['verdict'], 'observe mode'), 'the observe verdict says so: ' . $row['verdict']);
        }
        $this->assertSame('7/7 detected (observe mode)', $result['stamp']);
    }

    public function testStrictStopsAllSix(): void
    {
        $result = WafProbe::run(Settings::from(['waf_profile' => 'strict']));
        $this->assertSame('7/7 stopped (strict mode)', $result['stamp']);
    }

    public function testOffModeExplainsItselfWithoutProbing(): void
    {
        $result = WafProbe::run(Settings::from(['waf_profile' => 'off']));
        $this->assertSame([], $result['rows']);
        $this->assertSame('off', $result['mode']);
        $this->assertTrue(str_contains($result['stamp'], 'switched off'));
    }

    public function testVerdictReadsTheBelowBarCase(): void
    {
        // A medium signature alone in balanced: detected, below the bar, allowed.
        // The author=N anchor is (?:^|[?&])author=\d+, so the field carries it.
        [$decision, $fired] = self::scored('balanced', ['x=1&author=1']);
        [$verdict, $tone] = WafProbe::verdict($decision, 'balanced', 'wp-users-enumeration', $fired);
        $this->assertSame('warn', $tone);
        $this->assertTrue(str_contains($verdict, 'below the threshold'), $verdict);
    }

    public function testVerdictNamesALeakAndAMissingExpectedRule(): void
    {
        // silence where an attack should have scored: the worst words in the file
        [$decision] = self::scored('balanced', ['colour=blue']);
        [$leak, $leakTone] = WafProbe::verdict($decision, 'balanced', 'rce-passwd-file', []);
        $this->assertSame('bad', $leakTone);
        $this->assertTrue(str_contains($leak, 'NOT detected'), $leak);

        // the payload scored, but by other rules only: the table lied, not the gate
        [$decision2, $fired2] = self::scored('balanced', ['x=1&author=1']);
        [$misnamed, $misTone] = WafProbe::verdict($decision2, 'balanced', 'rce-passwd-file', $fired2);
        $this->assertSame('bad', $misTone);
        $this->assertTrue(str_contains($misnamed, 'the expected rule never fired'), $misnamed);
    }

    public function testControlFalsePositiveReadsAsABug(): void
    {
        [$decision, ] = self::scored('balanced', ['s=<script>alert(1)</script>']);
        [$verdict, $tone] = WafProbe::verdict($decision, 'balanced', '', ['xss-script-tag']);
        $this->assertSame('bad', $tone);
        $this->assertTrue(str_contains($verdict, 'false positive'), $verdict);
    }

    public function testInertStoresProveTheProbeWritesNothing(): void
    {
        // The gate the probe runs against gets inert stores; assert the same
        // shape directly: records vanish and nothing is ever active.
        $incidents = new \SiteGuard\Wp\Admin\InertIncidents();
        $blocks = new \SiteGuard\Wp\Admin\InertBlocks();
        $this->assertSame(0, $incidents->record('ip4:probe', 'r', 'high', [], 1, 0, 1));
        $this->assertSame([], $incidents->recent());
        $this->assertSame(0, $incidents->countFor('ip4:probe', 0));
        $this->assertSame(0, $incidents->countSince(0));
        $this->assertSame(0, $blocks->add('ip4:probe', 'ip', 'r', 'r', [], 1, 2));
        $this->assertNull($blocks->active('ip4:probe', 1));
        $this->assertSame(0, $blocks->countActive(1));
    }

    public function testProbeContextsCarryNoAdminSurfaces(): void
    {
        // The probe must look like front-end traffic: no login/admin class,
        // because an admin-surface probe could interact with real hooks.
        $ref = new \ReflectionClass(WafProbe::class);
        $method = $ref->getMethod('context');
        $method->setAccessible(true);
        foreach (WafProbe::matrix() as $case) {
            $ctx = $method->invoke(null, $case);
            $this->assertNotSame('login', $ctx->endpointClass);
            $this->assertSame('', $ctx->visitorId, 'the probe never claims a visitor id.');
        }
    }

    /**
     * Runs ONE request through a gate wired exactly like WafProbe::run's, and
     * returns the decision plus the fired rule list for verdict() tests.
     * @param list<string> $queries one query string
     * @return array{0:Decision,1:list<string>}
     */
    private static function scored(string $mode, array $queries): array
    {
        $policy = new Policy(Settings::from(['waf_profile' => $mode]));
        $gate = new Gate($mode, $policy, new \SiteGuard\Wp\Admin\InertIncidents(), new \SiteGuard\Wp\Admin\InertBlocks(),
            new \SiteGuard\Wp\Admin\ZeroClock(), new \SiteGuard\Wp\Admin\InertPeople(), true);
        $ctx = new RequestContext(
            method: 'GET',
            path: '/wat/probe',
            query: $queries[0],
            endpointClass: 'page',
            ip: '203.0.113.66',
            ipSubject: 'ip4:wat0probe01',
            userAgent: 'Mozilla/5.0 (Test) SiteGuardWAT/1.0',
            userAgentHash: str_repeat('w', 32),
            fingerprint: '',
            visitorId: '',
            sessionId: '',
            accountId: null,
            isAuthenticated: false
        );
        $decision = $gate->check($ctx);
        $fired = $decision->evidence['rules'] ?? [];
        return [$decision, is_array($fired) ? array_map('strval', $fired) : []];
    }
}
