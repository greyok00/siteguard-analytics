<?php
declare(strict_types=1);

namespace SiteGuard\Tests;

use SiteGuard\Core\Policy;
use SiteGuard\Core\Settings;

/**
 * Tests for policy resolution: profiles, account multipliers, retention
 * floors, and the block-ladder bounds.
 */
final class PolicyTest extends TestCase
{
    public function testBalancedIsTheDefaultAndEnforces(): void
    {
        $policy = new Policy(Settings::from([]));
        $this->assertSame(Policy::BALANCED, $policy->profile());
        $this->assertTrue($policy->enforces());
        $this->assertTrue($policy->enabled());
    }

    public function testObserveNeverEnforces(): void
    {
        $policy = new Policy(Settings::from(['profile' => 'observe']));
        $this->assertFalse($policy->enforces());
        $this->assertSame(0, $policy->distinctLimit(), 'Breadth rule is off in observe.');
    }

    public function testUnknownProfileFallsBackToBalanced(): void
    {
        $policy = new Policy(Settings::from(['profile' => 'whatever']));
        $this->assertSame(Policy::BALANCED, $policy->profile());
    }

    public function testRulesUseTheConfiguredWindows(): void
    {
        $policy = new Policy(Settings::from([]));
        $rules = $policy->rules('html', false);
        $this->assertSame([[10, 20], [60, 60], [3600, 600]], $rules);
    }

    public function testStrictHalvesTheLimits(): void
    {
        $policy = new Policy(Settings::from(['profile' => 'strict', 'strict_factor' => 0.5]));
        $this->assertSame([[10, 10], [60, 30], [3600, 300]], $policy->rules('html', false));
        $this->assertSame(75, $policy->distinctLimit());
    }

    public function testSignedInAccountsGetTheMultiplier(): void
    {
        $policy = new Policy(Settings::from(['account_multiplier' => 2.0]));
        $this->assertSame([[10, 40], [60, 120], [3600, 1200]], $policy->rules('html', true));
    }

    public function testLadderGrowsAndCaps(): void
    {
        $policy = new Policy(Settings::from(['block_ladder' => [300, 900, 3600]]));
        $this->assertSame(300, $policy->blockDuration(1));
        $this->assertSame(900, $policy->blockDuration(2));
        $this->assertSame(3600, $policy->blockDuration(3));
        $this->assertSame(3600, $policy->blockDuration(99), 'The last rung is a ceiling.');
    }

    public function testEmptyLadderFallsBack(): void
    {
        $policy = new Policy(Settings::from(['block_ladder' => []]));
        $this->assertSame(300, $policy->blockDuration(1));
    }

    public function testWatchlistEnforcedReadsSetting(): void
    {
        $this->assertTrue(
            (new Policy(Settings::from([])))->watchlistEnforced(),
            'The watchlist ships armed: true without any stored value.'
        );
        $this->assertFalse(
            (new Policy(Settings::from(['waf_watchlist' => false])))->watchlistEnforced(),
            'An owner who switched it off keeps it off.'
        );
        $this->assertTrue(
            (new Policy(Settings::from(['waf_watchlist' => 'garbage'])))->watchlistEnforced(),
            'A garbage value is truthy, same treatment as every other bool knob.'
        );
    }

    public function testRetentionHasAFloor(): void
    {
        $policy = new Policy(Settings::from(['retention' => ['events' => 0]]));
        $this->assertSame(1, $policy->retentionDays('events'));
        $this->assertSame(30, $policy->retentionDays('unknown'));
    }
}
