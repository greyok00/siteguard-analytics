<?php
declare(strict_types=1);

namespace SiteGuard\Tests;

use SiteGuard\Wp\Admin\CollectorProbe;

/**
 * The interpreter matrix: each transport's answer codes must read as plain
 * words on the diagnostics screen, and 403-on-REST must read distinctly from
 * "unreachable", because the 403 is the exact host kill-switch failure the
 * admin-ajax fallback exists to survive.
 */
final class CollectorProbeTest extends TestCase
{
    public function testRestInterpreterHasAVerdictForEveryAnswer(): void
    {
        $this->assertTrue(str_contains(CollectorProbe::interpretRest(204), 'healthy'), '204 is the collector reply; it must read as healthy.');
        $this->assertTrue(str_contains(CollectorProbe::interpretRest(403), '403'), 'the host kill switch code must be named, not hidden.');
        $this->assertTrue(str_contains(CollectorProbe::interpretRest(401), '401'), 'the host kill switch cousin code must be named too.');
        $this->assertTrue(str_contains(CollectorProbe::interpretRest(403), 'disabled'), 'the kill switch verdict must say what the host disabled.');
        $this->assertTrue(str_contains(CollectorProbe::interpretRest(0), 'unreachable'), 'code 0 means the request never completed.');
        $this->assertTrue(str_contains(CollectorProbe::interpretRest(500), 'unexpected'), 'anything else reads as unexpected, not as an invented meaning.');
    }

    public function testAjaxInterpreterMatchesTheFallbackStory(): void
    {
        $this->assertTrue(str_contains(CollectorProbe::interpretAjax(204), 'healthy'), 'a healthy fallback says so.');
        $this->assertTrue(str_contains(CollectorProbe::interpretAjax(0), 'broken'), 'an unreachable fallback must be called what it is: collection likely broken.');
        $this->assertTrue(str_contains(CollectorProbe::interpretAjax(302), 'unexpected'));
    }

    public function testKillSwitchVerdictNamesTheFallbackAsTheRescue(): void
    {
        $rest = CollectorProbe::interpretRest(403);
        $ajax = CollectorProbe::interpretAjax(204);
        $this->assertTrue(str_contains($rest, 'admin-ajax'), 'the REST verdict must point at the fallback transport.');
        $this->assertTrue(str_contains($ajax, 'fallback'), 'the fallback verdict must state its rescue role.');
    }
}
