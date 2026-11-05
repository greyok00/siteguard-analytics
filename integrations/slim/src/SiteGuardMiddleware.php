<?php
declare(strict_types=1);

namespace SiteGuard\Slim;

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use SiteGuard\Core\Classifier;
use SiteGuard\Core\Crypto;
use SiteGuard\Core\Decision;
use SiteGuard\Core\Enforcer;
use SiteGuard\Core\Ip;
use SiteGuard\Core\RequestContext;
use SiteGuard\Core\Settings;

/**
 * Slim 4 middleware using the same deterministic core as the WordPress build.
 *
 * Unlike WordPress, a Slim app sees a request before routing, so this
 * middleware really is the first thing that runs. It is the strongest of the
 * three integrations: nothing reaches the router or the database on a denial.
 */
final class SiteGuardMiddleware implements MiddlewareInterface
{
    public function __construct(
        private Enforcer $enforcer,
        private ResponseFactoryInterface $responseFactory,
        private SettingsProvider $settings,
        private Crypto $crypto
    ) {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $settings = $this->settings->get();
        if (empty($settings['enabled'])) {
            return $handler->handle($request);
        }

        $path = $request->getUri()->getPath();
        $query = $request->getUri()->getQuery();
        $method = strtoupper($request->getMethod());

        $headers = [];
        foreach ($request->getHeaders() as $name => $values) {
            $headers[$name] = implode(',', $values);
        }

        $remote = (string) ($request->getServerParams()['REMOTE_ADDR'] ?? '');
        $ip = Ip::client($remote, $headers, (string) ($settings['trusted_proxies'] ?? ''));
        $ua = substr((string) $request->getHeaderLine('User-Agent'), 0, 512);
        $uaHash = $ua === '' ? '' : substr($this->crypto->subject('ua', $ua), -32);

        $ctx = new RequestContext(
            method: $method,
            path: substr($path, 0, 255),
            query: substr($query, 0, 512),
            endpointClass: Classifier::classify([
                'path' => $path,
                'query' => $query,
                'method' => $method,
                'is_rest' => str_starts_with($path, '/api/') || str_contains($path, '/wp-json/'),
            ]),
            ip: $ip,
            ipSubject: Ip::subject($ip),
            userAgent: $ua,
            userAgentHash: $uaHash,
            fingerprint: '',
            visitorId: self::id($request->getCookieParams()['sg_v'] ?? ''),
            sessionId: self::id($request->getCookieParams()['sg_s'] ?? ''),
            accountId: null,
            isAuthenticated: false
        );

        try {
            $decision = $this->enforcer->check($ctx);
        } catch (\Throwable $e) {
            error_log('SiteGuard middleware: ' . $e->getMessage());
            return $handler->handle($request);
        }

        if (!$decision->denied()) {
            $response = $handler->handle($request);
            return $response->withHeader('X-SiteGuard-Rule', $decision->rule ?: 'allow');
        }

        return $this->deny($decision);
    }

    private static function id(mixed $value): string
    {
        $value = (string) $value;
        return Crypto::isId($value) ? $value : '';
    }

    private function deny(Decision $decision): ResponseInterface
    {
        $response = $this->responseFactory->createResponse($decision->status);
        $response->getBody()->write(json_encode([
            'error' => 'rate_limited',
            'message' => 'Too many requests. Try again later.',
            'retry_after' => $decision->retryAfter,
        ], JSON_THROW_ON_ERROR));
        return $response
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('Retry-After', (string) $decision->retryAfter)
            ->withHeader('Cache-Control', 'no-store')
            ->withHeader('X-SiteGuard', 'blocked');
    }
}

/** Supplies the settings array; wire it to a config file, env, or database. */
interface SettingsProvider
{
    /** @return array<string,mixed> */
    public function get(): array;
}

/** A simple fixed-array provider for tests and small apps. */
final class ArraySettings implements SettingsProvider
{
    /** @param array<string,mixed> $values */
    public function __construct(private array $values)
    {
    }

    public function get(): array
    {
        return Settings::from($this->values);
    }
}
