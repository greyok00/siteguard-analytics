<?php
declare(strict_types=1);

namespace SiteGuard\Core;





final class RequestContext
{
    public function __construct(
        public readonly string $method,
        public readonly string $path,
        public readonly string $query,
        public readonly string $endpointClass,
        
        public readonly string $ip,
        
        public readonly string $ipSubject,
        public readonly string $userAgent,
        public readonly string $userAgentHash,
        
        public readonly string $fingerprint,
        
        public readonly string $visitorId,
        public readonly string $sessionId,
        
        public readonly ?int $accountId,
        public readonly bool $isAuthenticated,
        
        public readonly bool $verifiedCrawler = false,
        public readonly bool $isBotLikely = false
    ) {
    }

    
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
