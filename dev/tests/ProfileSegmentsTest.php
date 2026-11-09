<?php
declare(strict_types=1);

namespace SiteGuard\Tests;

use SiteGuard\Core\Profile\Segments;

/**
 * The classification laws: one path gets exactly one topic with the right
 * rule winning, capability hints band correctly including unparseable input,
 * and a visitor's rhythm never mistakes a first week for a heavy habit.
 */
final class ProfileSegmentsTest extends TestCase
{
    public function testTopicsFollowTheFirstMatchWinsLaw(): void
    {
        $this->assertSame('pricing', Segments::topic('/pricing'), 'pricing is a topic of its own.');
        $this->assertSame('pricing', Segments::topic('/plans/annual'), 'plans pages are a buying signal, not shop.');
        $this->assertSame('shop', Segments::topic('/shop/widget'), 'a shop url stays a purchase-interest signal.');
        $this->assertSame('shop', Segments::topic('/product/widget/reviews'), 'product urls are shop even deep in a path.');
        $this->assertSame('docs', Segments::topic('/docs/install'), 'docs wins over article on documentation pages.');
        $this->assertSame('article', Segments::topic('/blog/2026/spring-launch'), 'the blog is the article vein.');
        $this->assertSame('contact', Segments::topic('/contact-us'), 'contact pages are a hand-raised signal.');
        $this->assertSame('other', Segments::topic('/'), 'the home page commits to no topic at all.');
    }

    public function testTopicCountsBucketTheCrowd(): void
    {
        $counts = Segments::topicCounts([
            '/shop/widget' => 40,
            '/pricing' => 25,
            '/' => 100,
            '/blog/launch' => 12,
        ]);
        $this->assertSame(40, $counts['shop']);
        $this->assertSame(25, $counts['pricing']);
        $this->assertSame(12, $counts['article']);
        $this->assertSame(100, $counts['other'], 'the home page lands under other.');
        foreach (Segments::TOPICS as $topic) {
            $this->assertTrue(array_key_exists($topic, $counts), 'topic totals exist per topic listed in the TOPICS law.');
        }
    }

    public function testCapabilityBandsReadTheHintsIncludingJunk(): void
    {
        $memory = Segments::memoryBands([
            ['mem' => '8'],
            ['mem' => '4'],
            ['mem' => '0.5'],
            ['mem' => ''],
            [],
            'nonsense',
        ]);
        $this->assertSame(1, $memory['large']);
        $this->assertSame(1, $memory['mid']);
        $this->assertSame(1, $memory['small']);
        $this->assertSame($memory['small'] + $memory['mid'] + $memory['large'] + $memory['unknown'], 6, 'every profile lands in exactly one band.');

        $cores = Segments::coresBands([
            ['cores' => 12],
            ['cores' => 6],
            ['cores' => 2],
            ['cores' => ''],
        ]);
        $this->assertSame(1, $cores['high']);
        $this->assertSame(1, $cores['mid']);
        $this->assertSame(1, $cores['low']);
        $this->assertSame(1, $cores['unknown'], 'an unreported hint is named, never guessed.');
    }

    public function testPaceNeverCallsAFirstWeekHeavy(): void
    {
        $now = 1790000000;
        $week = 7 * 86400;
        $this->assertSame('new', Segments::pace(30, $now - $week / 2, $now), 'a burst of sessions in the first week is still a new visitor.');
        $this->assertSame('new', Segments::pace(0, $now - 10 * $week, $now), 'no sessions yet is still new.');
        $this->assertSame('light', Segments::pace(2, $now - 3 * $week, $now), 'two sessions in three weeks is under one a week.');
        $this->assertSame('steady', Segments::pace(6, $now - 2 * $week, $now), 'three a week sits in the steady band.');
        $this->assertSame('heavy', Segments::pace(50, $now - $week, $now), 'fifty in a mature week is a heavy regular.');
    }
}
