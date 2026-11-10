<?php
declare(strict_types=1);

namespace SiteGuard\Tests;


use SiteGuard\Core\Policy;
use SiteGuard\Core\RequestContext;
use SiteGuard\Core\Settings;
use SiteGuard\Core\Subjects;
use SiteGuard\Core\Waf\Gate;

/**
 * Profile matrix and the never-regress laws: observe records without denying,
 * balanced/strict thresholds, crawler and scanner-UA treatment, the visitor-id
 * forgery law, the authenticated observe-only law, and expiring blocks.
 */
final class WafGateTest extends TestCase
{
    /** @return array{0:Gate,1:FakeClock,2:SqliteBlocks,3:SqliteIncidents,4:SqliteDb,5:SqlitePeople} */
    private function make(string $mode, int $now = 1700000000, bool $deviceHints = true): array
    {
        $clock = new FakeClock($now);
        $db = new SqliteDb();
        $blocks = new SqliteBlocks($db->pdo);
        $incidents = new SqliteIncidents($db->pdo);
        $people = new SqlitePeople($db->pdo);
        $settings = Settings::from([]);
        $settings['waf_profile'] = $mode;
        $gate = new Gate($mode, new Policy($settings), $incidents, $blocks, $clock, $people, $deviceHints);
        return [$gate, $clock, $blocks, $incidents, $db, $people];
    }

    public function testObserveRecordsButNeverDenies(): void
    {
        [$gate, , $blocks, $incidents] = $this->make('observe');
        $ctx = Support::context(['path' => '/download', 'query' => 'file=../../../etc/passwd']);
        $decision = $gate->check($ctx);
        $this->assertTrue($decision->allowed, 'observe mode must never deny.');
        $this->assertSame('observe', $decision->reason);
        $this->assertCount(0, $incidents->recent(1700000000, 60) ?: []);
        $rows = $incidents->countSince(1700000000 - 3600);
        $this->assertSame(1, $rows, 'observe mode records the hit exactly once.');
        $this->assertSame(0, $blocks->countActive(1700000000), 'observe mode never stores a block.');
    }

    public function testBalancedBlocksCriticalAndHighSignatures(): void
    {
        [$gate, $clock, $blocks, $incidents] = $this->make('balanced');
        foreach ([
            '/download' => 'file=../../../etc/passwd',     // rce CRITICAL
            '/wp-config' => 's=<script>alert(1)</script>', // xss HIGH
        ] as $path => $query) {
            $ctx = Support::context(['path' => $path, 'query' => $query]);
            $decision = $gate->check($ctx);
            $this->assertTrue($decision->denied(), 'balanced must block severity>=4: ' . $path);
            $this->assertSame(429, $decision->status);
            $this->assertSame('blocked', $decision->reason);
            $this->assertSame('ip', $decision->scope);
            $this->assertTrue($decision->retryAfter >= 300, 'duration comes from the ladder floor.');
        }
        $subject = \SiteGuard\Core\Subjects::ip(Support::context([])->ipSubject);
        $this->assertSame(1, $blocks->countActive($clock->now()), 'one subject, one block row.');
        $this->assertSame(1, $incidents->countSince(1700000000 - 60), 'the block records one incident; the reuse of the running block records none.');
    }

    public function testStrictBlocksMediumSignaturesBalancedDoesNot(): void
    {
        $ctx = Support::context(['path' => '/', 'query' => 'author=1']); // wp-abuse MEDIUM

        [$gate ] = $this->make('balanced');
        $balanced = $gate->check($ctx);
        $this->assertTrue($balanced->allowed, 'balanced must not block a medium-only signature.');

        [$gate, , $blocks] = $this->make('strict');
        $strict = $gate->check($ctx);
        $this->assertTrue($strict->denied(), 'strict must block a medium signature.');
        $this->assertSame(1, $blocks->countActive(1700000000));
    }

    public function testVerifiedCrawlerPassesEvenWithProbePayload(): void
    {
        [$gate, , $blocks] = $this->make('balanced');
        $ctx = Support::context([
            'path' => '/download',
            'query' => 'file=../../../etc/passwd',
            'userAgent' => 'sqlmap/1.8',
            'verifiedCrawler' => true,
        ]);
        $decision = $gate->check($ctx);
        $this->assertTrue($decision->allowed, 'reverse-DNS-verified crawler is never punished.');
        $this->assertSame(0, $blocks->countActive(1700000000));
    }

    public function testScannerUaAloneNeverBlocks(): void
    {
        [$gate] = $this->make('balanced');
        $ctx = Support::context([
            'path' => '/products/widget',
            'query' => 'colour=blue',
            'userAgent' => 'sqlmap/1.8',
        ]);
        $decision = $gate->check($ctx);
        $this->assertTrue($decision->allowed, 'a scanner UA without a probe hit is not an attack.');
    }

    public function testVisitorIdSubjectCanNeverBeBlocked(): void
    {
        [$gate, , $blocks] = $this->make('balanced');
        $ctx = Support::context([
            'ipSubject' => '',
            'visitorId' => str_repeat('7', 32),
            'path' => '/download',
            'query' => 'file=../../../etc/passwd',
        ]);
        $decision = $gate->check($ctx);
        $this->assertTrue($decision->allowed, 'a forged visitor id can never buy a block.');
        $this->assertSame(0, $blocks->countActive(1700000000), 'no block row exists for a visitor subject.');
    }

    public function testAuthenticatedNonAdminIsObservedNeverDenied(): void
    {
        [$gate, , $blocks] = $this->make('balanced');
        $ctx = Support::context([
            'path' => '/shop/checkout',
            'query' => 'note=union select shipping',
            'isAuthenticated' => true,
            'accountId' => 51,
        ]);
        $decision = $gate->check($ctx);
        $this->assertTrue($decision->allowed, 'a signed-in non-admin must never be content-denied.');
        $this->assertSame('observe', $decision->reason);
        $this->assertSame(0, $blocks->countActive(1700000000));
    }

    public function testBelowThresholdHitsAreRecordedAndAllowed(): void
    {
        [$gate, , , $incidents] = $this->make('balanced');
        $ctx = Support::context(['path' => '/xmlrpc.php']);
        $decision = $gate->check($ctx);
        $this->assertTrue($decision->allowed, 'xmlrpc usage alone is LOW and stays below the balanced bar.');
        $this->assertSame(1, $incidents->countSince(1700000000 - 3600), 'a below-threshold probe is recorded for visibility but never denied.');
    }

    public function testAnomalyOnlyHitNeverSatisfiesAnyThreshold(): void
    {
        [$gate, , $blocks] = $this->make('strict');
        $ctx = Support::context(['path' => '/search', 'query' => 's=' . str_repeat('A', 3000)]);
        $decision = $gate->check($ctx);
        $this->assertTrue($decision->allowed, 'an anomaly-only request can never be denied, even in strict.');
        $this->assertSame(0, $blocks->countActive(1700000000));
    }

    public function testOffModeStoresNothingAtAll(): void
    {
        [$gate, , $blocks, $incidents] = $this->make('off');
        $ctx = Support::context(['path' => '/download', 'query' => 'file=../../../etc/passwd']);
        $decision = $gate->check($ctx);
        $this->assertTrue($decision->allowed);
        $this->assertSame(0, $blocks->countActive(1700000000));
        $this->assertSame(0, $incidents->countSince(1700000000 - 3600));
    }

    public function testBlockLadderClimbsOnRepeatEscalations(): void
    {
        [$gate, $clock] = $this->make('balanced');
        $makeCtx = fn () => Support::context([
            'path' => '/download',
            'query' => 'file=../../../etc/passwd',
            'ipSubject' => 'ip4:deadbeef',
        ]);

        $first = $gate->check($makeCtx());
        $this->assertSame(300, $first->retryAfter, 'first rung of the ladder is 300s.');

        // Inside the running block every later request reuses it, gaining no
        // fresh rows; the ladder climbs when the block expires and returns.
        $clock->set(1700000000 + 300 + 1);
        $second = $gate->check($makeCtx());
        $this->assertSame(900, $second->retryAfter, 'second offence after expiry climbs to 900s.');

        $clock->set(1700000000 + 300 + 1 + 900 + 1);
        $third = $gate->check($makeCtx());
        $this->assertSame(3600, $third->retryAfter, 'third offence climbs to 3600s.');
    }

    public function testIncidentRecordingIsThrottledPerSubject(): void
    {
        [$gate, $clock, , $incidents] = $this->make('observe');
        $ctx = Support::context(['path' => '/download', 'query' => 'file=../../../etc/passwd', 'ipSubject' => 'ip4:feedbeef']);

        $gate->check($ctx);
        $clock->set(1700000100); // +100s, inside the throttle window
        $gate->check($ctx);
        $this->assertSame(1, $incidents->countSince(1699999400), 'one incident per subject per throttle window.');

        $clock->set(1700000400); // beyond the 300s window
        $gate->check($ctx);
        $this->assertSame(2, $incidents->countSince(1699999400), 'a later window records again.');
    }

    public function testActiveBlockShortCircuitsLaterRequests(): void
    {
        [$gate] = $this->make('balanced');
        $ctx = Support::context(['path' => '/download', 'query' => 'file=../../../etc/passwd', 'ipSubject' => 'ip4:cafe0bad']);
        $this->assertTrue($gate->check($ctx)->denied());
        $blockCheck = $gate->check(Support::context(['path' => '/products/widget', 'ipSubject' => 'ip4:cafe0bad']));
        $this->assertTrue($blockCheck->denied(), 'an existing block still denies through the WAF path.');
        $this->assertSame('blocked', $blockCheck->reason);
    }

    public function testStoredDeviceLiesDenyOnTheSecondVisit(): void
    {
        [$gate, , $blocks, , , $people] = $this->make('balanced');
        $visitorId = str_repeat('9', 32);
        $people->setProfile($visitorId, ['platform' => 'iPhone', 'ua_platform' => 'iOS', 'ua_mobile' => '1', 'touch' => '0']);

        $first = $gate->check(Support::context(['path' => '/products/widget', 'visitorId' => $visitorId]));
        $this->assertTrue($first->denied(), 'a stored touch-free iPhone is a denial signature in balanced.');
        $this->assertSame('fp-touchless-ios', $first->rule, 'the incident names the fingerprint rule.');
        $this->assertSame('ip', $first->scope, 'the block lands on the address, never the visitor id.');
        $this->assertSame(1, $blocks->countActive(1700000000));
    }

    public function testDeviceHintOffLeavesProfileEvidenceInert(): void
    {
        [$gate, , $blocks, $incidents, , $people] = $this->make('balanced', 1700000000, false);
        $visitorId = str_repeat('9', 32);
        $people->setProfile($visitorId, ['platform' => 'iPhone', 'ua_platform' => 'iOS', 'ua_mobile' => '1', 'touch' => '0']);
        $decision = $gate->check(Support::context(['path' => '/products/widget', 'visitorId' => $visitorId]));
        $this->assertFalse($decision->denied(), 'the toggle is a real off switch, not a suggestion.');
        $this->assertSame(0, $blocks->countActive(1700000000));
        $this->assertSame(0, $incidents->countSince(1700000000 - 3600));
    }

    public function testDeviceHintsRecordInObserveAndPassInOff(): void
    {
        [$observe, , , $incidents, , $people] = $this->make('observe');
        $visitorId = str_repeat('9', 32);
        $people->setProfile($visitorId, ['platform' => 'iPhone', 'ua_platform' => 'iOS', 'ua_mobile' => '1', 'touch' => '0']);
        $ctx = Support::context(['path' => '/products/widget', 'visitorId' => $visitorId]);
        $decision = $observe->check($ctx);
        $this->assertFalse($decision->denied(), 'observe records, never denies.');
        $this->assertSame(1, $incidents->countSince(1700000000 - 3600), 'the lie is on the record.');

        [$off, , , $offIncidents, , $offPeople] = $this->make('off');
        $offPeople->setProfile($visitorId, ['platform' => 'iPhone', 'ua_platform' => 'iOS', 'ua_mobile' => '1', 'touch' => '0']);
        $this->assertFalse($off->check($ctx)->denied());
        $this->assertSame(0, $offIncidents->countSince(1700000000 - 3600));
    }

    public function testFirstVisitHasNoStoredProfileAndPasses(): void
    {
        [$gate, , $blocks, $incidents] = $this->make('balanced');
        $decision = $gate->check(Support::context(['path' => '/products/widget', 'visitorId' => str_repeat('9', 32)]));
        $this->assertFalse($decision->denied(), 'no stored profile, no profile hits: the first visit is never denied for one.');
        $this->assertSame(0, $blocks->countActive(1700000000));
        $this->assertSame(0, $incidents->countSince(1700000000 - 3600));
    }

    public function testForgedVisitorIdWithLyingProfileStillBlocksOnlyTheAddress(): void
    {
        [$gate, , $blocks, , , $people] = $this->make('balanced');
        $visitorId = str_repeat('9', 32);
        // a HIGH device lie: the lone hit stands at maxSeverity 4 >= the balanced bar 4
        $people->setProfile($visitorId, ['platform' => 'iPhone', 'ua_platform' => 'iOS', 'ua_mobile' => '1', 'touch' => '0']);
        $decision = $gate->check(Support::context([
            'path' => '/products/widget',
            'visitorId' => $visitorId,
            'ipSubject' => 'ip4:cafe0bad',
        ]));
        $this->assertTrue($decision->denied(), 'stored lies score against the request.');
        $this->assertSame('ip', $decision->scope, 'the forged id cannot redirect the block at a visitor subject.');
        $this->assertSame(1, $blocks->countActive(1700000000), 'exactly one row, for the address.');
        $active = $blocks->active('ip4:cafe0bad', 1700000000);
        $this->assertTrue($active !== null, 'the row belongs to the address.');
        $visitorRow = $blocks->active(Subjects::VISITOR_PREFIX . str_repeat('9', 32), 1700000000);
        $this->assertTrue($visitorRow === null, 'no row for the visitor id.');
    }

    public function testMalformedStoredProfileActsClean(): void
    {
        [$gate, , $blocks, , $db, $people] = $this->make('balanced');
        $visitorId = str_repeat('9', 32);
        // raw junk instead of JSON goes straight into the column; profileFor
        // must decode-fail to [] and the gate must treat that as silence
        $stmt = $db->pdo->prepare("INSERT INTO people (id, profile) VALUES (:id, :p)");
        $stmt->execute([':id' => $visitorId, ':p' => '{not json']);
        $decision = $gate->check(Support::context(['path' => '/products/widget', 'visitorId' => $visitorId]));
        $this->assertFalse($decision->denied(), 'a malformed stored profile is absence of evidence, not evidence.');
        $this->assertSame([], $people->profileFor($visitorId));
        $this->assertSame(0, $blocks->countActive(1700000000));
    }

    public function testAuthenticatedSubjectIsObservedEvenWithLyingProfile(): void
    {
        [$gate, , $blocks, , , $people] = $this->make('balanced');
        $visitorId = str_repeat('9', 32);
        $people->setProfile($visitorId, ['platform' => 'iPhone', 'ua_platform' => 'iOS', 'ua_mobile' => '1', 'touch' => '0']);
        $decision = $gate->check(Support::context([
            'path' => '/shop/checkout',
            'visitorId' => $visitorId,
            'isAuthenticated' => true,
            'accountId' => 51,
        ]));
        $this->assertFalse($decision->denied(), 'signed-in non-admins are never content-denied, profile lies included.');
        $this->assertSame(0, $blocks->countActive(1700000000));
    }
}
