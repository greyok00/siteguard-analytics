<?php
declare(strict_types=1);

namespace SiteGuard\Tests;

use SiteGuard\Core\Classifier;
use SiteGuard\Core\RequestContext;

final class Support
{
    /** @param array<string,mixed> $overrides */
    public static function context(array $overrides = []): RequestContext
    {
        $path = (string) ($overrides['path'] ?? '/');
        $query = (string) ($overrides['query'] ?? '');
        $class = (string) ($overrides['endpointClass'] ?? Classifier::classify([
            'path' => $path,
            'query' => $query,
            'method' => (string) ($overrides['method'] ?? 'GET'),
        ]));

        return new RequestContext(
            method: (string) ($overrides['method'] ?? 'GET'),
            path: $path,
            query: $query,
            endpointClass: $class,
            ip: (string) ($overrides['ip'] ?? '203.0.113.10'),
            ipSubject: (string) ($overrides['ipSubject'] ?? 'ip4:cb0071' . '0a'),
            userAgent: (string) ($overrides['userAgent'] ?? 'Mozilla/5.0 Test'),
            userAgentHash: (string) ($overrides['userAgentHash'] ?? str_repeat('a', 32)),
            fingerprint: (string) ($overrides['fingerprint'] ?? ''),
            visitorId: (string) ($overrides['visitorId'] ?? ''),
            sessionId: (string) ($overrides['sessionId'] ?? ''),
            accountId: $overrides['accountId'] ?? null,
            isAuthenticated: (bool) ($overrides['isAuthenticated'] ?? false),
            verifiedCrawler: (bool) ($overrides['verifiedCrawler'] ?? false),
            isBotLikely: (bool) ($overrides['isBotLikely'] ?? false)
        );
    }

    /** @param array<string,mixed> $overrides */
    public static function settings(array $overrides = []): array
    {
        return \SiteGuard\Core\Settings::from($overrides);
    }
}
