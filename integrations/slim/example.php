<?php
declare(strict_types=1);

/**
 * Minimal Slim 4 wiring. Run:
 *
 *     composer require slim/slim slim/psr7
 *     php -S 127.0.0.1:8080 example.php
 *
 * Then request the same path repeatedly — the eleventh request inside ten
 * seconds is denied for the HTML profile with the default settings.
 *
 * The core classes are shared with the WordPress plugin. In a real project,
 * copy `plugin/siteguard-analytics/src/Core` into your source tree or add it
 * to Composer's autoload, then point the PSR-4 mapping at it.
 */

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use SiteGuard\Core\Crypto;
use SiteGuard\Core\Enforcer;
use SiteGuard\Core\Policy;
use SiteGuard\Core\Settings;
use SiteGuard\Core\SystemClock;
use SiteGuard\Slim\ArraySettings;
use SiteGuard\Slim\PdoBlocks;
use SiteGuard\Slim\PdoCounters;
use SiteGuard\Slim\PdoDistinct;
use SiteGuard\Slim\PdoIncidents;
use SiteGuard\Slim\SiteGuardMiddleware;
use Slim\Factory\AppFactory;

require __DIR__ . '/vendor/autoload.php';
require __DIR__ . '/../../plugin/siteguard-analytics/src/Core/autoload.php';
require __DIR__ . '/src/PdoStores.php';
require __DIR__ . '/src/SiteGuardMiddleware.php';

$pdo = new PDO('sqlite:' . __DIR__ . '/siteguard.sqlite');
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$pdo->exec((string) file_get_contents(__DIR__ . '/schema.sqlite.sql'));

$settings = new ArraySettings([
    'profile' => 'balanced',
    // Set this to your reverse proxy's range when the app is behind one.
    'trusted_proxies' => '',
]);

$enforcer = new Enforcer(
    new Policy(Settings::from($settings->get())),
    new PdoCounters($pdo),
    new PdoDistinct($pdo),
    new PdoBlocks($pdo),
    new SystemClock(),
    new PdoIncidents($pdo)
);

// Two rotating secrets; keep them in the environment and rotate them together
// with the data they key.
$crypto = new Crypto(
    getenv('SITEGUARD_SALT') ?: str_repeat('0', 64),
    getenv('SITEGUARD_FP_SALT') ?: str_repeat('1', 64),
    1
);

$app = AppFactory::create();
$app->add(new SiteGuardMiddleware($enforcer, $app->getResponseFactory(), $settings, $crypto));

$app->get('/', static function (ServerRequestInterface $request, ResponseInterface $response): ResponseInterface {
    $response->getBody()->write('Hello from the protected app.');
    return $response;
});

$app->run();
