<?php
declare(strict_types=1);

namespace SiteGuard\Tests;

use SiteGuard\Core\Enforcer;
use SiteGuard\Core\Policy;
use SiteGuard\Core\RequestContext;
use SiteGuard\Core\Settings;

/**
 * Tests for the enforcer: limit behaviour, block reuse and expiry, the block
 * ladder, breadth detection, and the disabled and unmanaged paths.
 */
final class EnforcerTest extends TestCase
{
    /** @return array{0:Enforcer,1:FakeClock,2:SqliteBlocks,3:SqliteIncidents,4:SqliteDb} */
    private function make(array $settings = [], int $now = 1700000000): array
    {
        $clock = new FakeClock($now);
        $db = new SqliteDb();
        $counters = new SqliteCounters($db->pdo, $clock);
        $distinct = new SqliteDistinct($db->pdo);
        $blocks = new SqliteBlocks($db->pdo);
        $incidents = new SqliteIncidents($db->pdo);
        $enforcer = new Enforcer(
            new Policy(Settings::from($settings)),
            $counters,
            $distinct,
            $blocks,
            $clock,
            $incidents
        );
        return [$enforcer, $clock, $blocks, $incidents, $db];
    }

    private function hit(Enforcer $enforcer, RequestContext $ctx): \SiteGuard\Core\Decision
    {
        return $enforcer->check($ctx);
    }

    public function testAllowsUntilTheBurstLimit(): void
    {
        [$enforcer] = $this->make();
        $ctx = Support::context(['path' => '/']);

        for ($i = 1; $i <= 20; $i++) {
            $decision = $this->hit($enforcer, $ctx);
            $this->assertTrue($decision->allowed, "Request $i should be allowed.");
        }

        $decision = $this->hit($enforcer, $ctx);
        $this->assertTrue($decision->denied(), 'The 21st request in ten seconds must be denied.');
        $this->assertSame(429, $decision->status);
        $this->assertSame('rate_10s', $decision->rule);
        $this->assertTrue($decision->retryAfter >= 1);
    }

    public function testBlockIsReusedForFollowingRequests(): void
    {
        [$enforcer, , $blocks] = $this->make();
        $ctx = Support::context(['path' => '/']);
        for ($i = 0; $i <= 20; $i++) {
            $this->hit($enforcer, $ctx);
        }

        $block = $blocks->active('ip4:cb00710a', 1700000000);
        $this->assertNotNull($block, 'A block row must exist after the denial.');

        $again = $this->hit($enforcer, $ctx);
        $this->assertTrue($again->denied());
        $this->assertSame('rate_10s', $again->rule, 'The replayed denial names the rule that caused it.');
        $this->assertSame(300, $again->retryAfter, 'Retry-After is the block expiry, not a fixed 1 second.');
        $this->assertSame(1, $blocks->countActive(1700000000), 'Only one block row per subject.');
    }

    public function testBlockExpiresOnItsOwn(): void
    {
        [$enforcer, $clock] = $this->make();
        $ctx = Support::context(['path' => '/']);
        for ($i = 0; $i <= 20; $i++) {
            $this->hit($enforcer, $ctx);
        }
        $this->assertTrue($this->hit($enforcer, $ctx)->denied());

        $clock->advance(301);
        $this->assertTrue(
            $this->hit($enforcer, $ctx)->allowed,
            'No block is permanent; 300 seconds later the client is served again.'
        );
    }

    public function testLadderEscalatesWhileCapped(): void
    {
        [$enforcer, $clock] = $this->make(['block_ladder' => [300, 900]]);
        $ctx = Support::context(['path' => '/']);

        for ($i = 0; $i <= 20; $i++) {
            $this->hit($enforcer, $ctx);
        }
        $first = $this->hit($enforcer, $ctx);
        $this->assertSame(429, $first->status);

        $clock->advance(301);
        for ($i = 0; $i <= 20; $i++) {
            $this->hit($enforcer, $ctx);
        }
        $second = $this->hit($enforcer, $ctx);
        $this->assertSame(900, $second->retryAfter, 'The second block uses the next rung.');
    }

    public function testLadderKeepsClimbingPastTheSecondRung(): void
    {
        [$enforcer, $clock] = $this->make(['block_ladder' => [300, 900, 3600, 21600]]);
        $ctx = Support::context(['path' => '/']);

        foreach ([300, 900, 3600, 21600] as $rung => $seconds) {
            for ($i = 0; $i <= 20; $i++) {
                $this->hit($enforcer, $ctx);
            }
            $decision = $this->hit($enforcer, $ctx);
            $this->assertSame(429, $decision->status, 'Violation ' . ($rung + 1) . ' must be denied.');
            $this->assertSame(
                $seconds,
                $decision->retryAfter,
                'Violation ' . ($rung + 1) . ' uses the documented rung.'
            );
            $clock->advance($seconds + 1);
        }
    }

    public function testObserveModeNeverDeniesOrBlocks(): void
    {
        [$enforcer, , $blocks, $incidents] = $this->make(['profile' => 'observe']);
        $ctx = Support::context(['path' => '/']);

        $denied = 0;
        for ($i = 0; $i <= 40; $i++) {
            $decision = $this->hit($enforcer, $ctx);
            if ($decision->denied()) {
                $denied++;
            }
        }
        $this->assertSame(0, $denied, 'Observe mode must never deny.');
        $this->assertSame(0, $blocks->countActive(1700000000));
        $this->assertCount(0, $incidents->rows);
    }

    public function testObservedRequestsAreStillCounted(): void
    {
        [$enforcer, , , , $db] = $this->make(['profile' => 'observe']);
        $ctx = Support::context(['path' => '/']);
        for ($i = 0; $i < 5; $i++) {
            $this->hit($enforcer, $ctx);
        }
        $count = (int) $db->pdo->query('SELECT SUM(n) FROM counters')->fetchColumn();
        $this->assertTrue($count >= 15, 'Each request advances all three windows.');
    }

    public function testVerifiedCrawlerIsNotLimited(): void
    {
        [$enforcer] = $this->make();
        $ctx = Support::context(['path' => '/', 'verifiedCrawler' => true]);
        for ($i = 0; $i < 50; $i++) {
            $this->assertTrue($this->hit($enforcer, $ctx)->allowed);
        }
    }

    public function testBrowserIdentityAloneNeverCreatesABlock(): void
    {
        [$enforcer, , $blocks] = $this->make();
        $ctx = Support::context([
            'path' => '/',
            'ipSubject' => '',
            'visitorId' => str_repeat('b', 32),
        ]);
        for ($i = 0; $i <= 20; $i++) {
            $this->hit($enforcer, $ctx);
        }
        $decision = $this->hit($enforcer, $ctx);
        $this->assertTrue($decision->denied());
        $this->assertSame('quota', $decision->reason, 'A forged visitor id may only get a short denial.');
        $this->assertSame(0, $blocks->countActive(1700000000), 'Browser telemetry must not create bans.');
    }

    public function testBreadthRuleTriggersOnDistinctPaths(): void
    {
        [$enforcer] = $this->make(['distinct_limit' => 3, 'distinct_window' => 600]);
        $decisions = [];
        foreach (['/a', '/b', '/c', '/d'] as $path) {
            $decisions[] = $this->hit($enforcer, Support::context(['path' => $path]));
        }
        $this->assertTrue($decisions[2]->allowed, 'Three distinct paths are within the limit.');
        $this->assertTrue($decisions[3]->denied(), 'The fourth distinct path exceeds it.');
        $this->assertSame('breadth_600s', $decisions[3]->rule);
    }

    public function testBreadthCanBeDisabled(): void
    {
        [$enforcer] = $this->make(['distinct_limit' => 0]);
        for ($i = 0; $i < 10; $i++) {
            $this->assertTrue($this->hit($enforcer, Support::context(['path' => '/p' . $i]))->allowed);
        }
    }

    public function testDisabledSettingsAllowEverything(): void
    {
        [$enforcer] = $this->make(['enabled' => false]);
        $ctx = Support::context(['path' => '/']);
        for ($i = 0; $i < 60; $i++) {
            $this->assertTrue($this->hit($enforcer, $ctx)->allowed);
        }
    }

    public function testUnmanagedClassesAreSkipped(): void
    {
        [$enforcer] = $this->make();
        $ctx = Support::context(['path' => '/wp-admin/', 'endpointClass' => 'admin']);
        for ($i = 0; $i < 60; $i++) {
            $this->assertTrue($this->hit($enforcer, $ctx)->allowed);
        }
    }

    public function testSignedInAccountIsBlockedAsAnAccount(): void
    {
        [$enforcer, , $blocks] = $this->make(['account_multiplier' => 1.0]);
        $ctx = Support::context([
            'path' => '/',
            'accountId' => 7,
            'isAuthenticated' => true,
        ]);
        for ($i = 0; $i <= 20; $i++) {
            $this->hit($enforcer, $ctx);
        }
        $decision = $this->hit($enforcer, $ctx);
        $this->assertTrue($decision->denied());
        $this->assertSame('account', $decision->scope);
        $this->assertNotNull($blocks->active('a:7', 1700000000));
    }

    public function testLoginRuleIsTighter(): void
    {
        [$enforcer] = $this->make();
        $ctx = Support::context(['path' => '/wp-login.php']);
        for ($i = 0; $i < 5; $i++) {
            $this->assertTrue($this->hit($enforcer, $ctx)->allowed, "Login attempt $i allowed.");
        }
        $decision = $this->hit($enforcer, $ctx);
        $this->assertTrue($decision->denied(), 'The sixth login attempt in ten seconds is denied.');
        $this->assertSame('rate_10s', $decision->rule);
    }

    public function testCounterKeysDoNotShareACollidingWindowStart(): void
    {
        // 60 and 3600 share a start at the top of the hour; the key must keep
        // them apart or the shorter window inherits the longer one's count.
        $start = 1700001600;
        $this->assertNotSame(
            \SiteGuard\Core\Subjects::counterKey('html', 'ip4:cb00710a', 60, $start),
            \SiteGuard\Core\Subjects::counterKey('html', 'ip4:cb00710a', 3600, $start)
        );
    }

    public function testUnattributableRequestsAreAllowed(): void
    {
        [$enforcer] = $this->make();
        $ctx = Support::context(['path' => '/', 'ipSubject' => '', 'visitorId' => '']);
        for ($i = 0; $i < 30; $i++) {
            $this->assertTrue($this->hit($enforcer, $ctx)->allowed);
        }
    }
}
