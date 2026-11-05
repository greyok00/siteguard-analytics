<?php
declare(strict_types=1);

namespace SiteGuard\Core;

/**
 * Everything the policy engine may consider about one request, resolved once.
 * Fields the adapter cannot verify stay null rather than being guessed.
 */
final class RequestContext
{
    public function __construct(
        public readonly string $method,
        public readonly string $path,
        public readonly string $query,
        public readonly string $endpointClass,
        /** Canonical client address, or '' when unknown. */
        public readonly string $ip,
        /** Counter subject derived from the address (/64 for IPv6). */
        public readonly string $ipSubject,
        public readonly string $userAgent,
        public readonly string $userAgentHash,
        /** Versioned passive-correlation hash, or '' when not collected. */
        public readonly string $fingerprint,
        /** First-party pseudonymous browser identifier, or ''. */
        public readonly string $visitorId,
        public readonly string $sessionId,
        /** Authenticated WordPress account, resolved server-side. */
        public readonly ?int $accountId,
        public readonly bool $isAuthenticated,
        /** Set only by a verified crawler check, never by the UA alone. */
        public readonly bool $verifiedCrawler = false,
        public readonly bool $isBotLikely = false
    ) {
    }

    /** A short, safe description for logs and the dashboard. */
    public function summary(): array
    {
        return [
            'method' => $this->method,
            'path' => $this->path,
            'class' => $this->endpointClass,
            'ip' => $this->ip,
            'account' => $this->accountId,
        ];
    }
}
