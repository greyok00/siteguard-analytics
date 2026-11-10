<?php
declare(strict_types=1);

/**
 * Dependency-free runner.
 *
 *     php dev/tests/run.php            # everything
 *     php dev/tests/run.php Enforcer   # files matching a substring
 *
 * Exit code is 0 only when every assertion passed.
 */

$root = dirname(__DIR__, 2);
// The plugin's autoloader is rooted at SITEGUARD_DIR and refuses to load unless
// ABSPATH is defined, which WordPress normally provides. The tests load Core
// directly, so both constants are defined here.
if (!defined('ABSPATH')) {
    define('ABSPATH', $root . '/');
}
if (!defined('SITEGUARD_DIR')) {
    define('SITEGUARD_DIR', $root . '/plugin/grey-siteguard/');
}
require $root . '/plugin/grey-siteguard/src/Core/autoload.php';
require __DIR__ . '/TestCase.php';
require __DIR__ . '/SqliteStores.php';
require __DIR__ . '/Support.php';

$filter = $argv[1] ?? '';
$passed = 0;
$failed = 0;
$assertions = 0;
$failures = [];

$files = glob(__DIR__ . '/*Test.php') ?: [];
sort($files);

foreach ($files as $file) {
    if ($filter !== '' && stripos(basename($file), $filter) === false) {
        continue;
    }
    require_once $file;
}

$classes = array_filter(get_declared_classes(), static function (string $class): bool {
    return str_starts_with($class, 'SiteGuard\\Tests\\') && str_ends_with($class, 'Test');
});

foreach ($classes as $class) {
    $reflection = new ReflectionClass($class);
    if ($reflection->isAbstract()) {
        continue;
    }
    if ($filter !== '' && stripos($class, $filter) === false) {
        continue;
    }

    foreach ($reflection->getMethods(ReflectionMethod::IS_PUBLIC) as $method) {
        if (!str_starts_with($method->getName(), 'test')) {
            continue;
        }
        /** @var \SiteGuard\Tests\TestCase $instance */
        $instance = new $class();
        $label = $reflection->getShortName() . '::' . $method->getName();

        try {
            $instance->setUp();
            $method->invoke($instance);
            $instance->tearDown();
        } catch (\Throwable $e) {
            $instance->failures[] = sprintf(
                'Uncaught %s: %s (%s:%d)',
                $e::class,
                $e->getMessage(),
                basename($e->getFile()),
                $e->getLine()
            );
        }

        $assertions += $instance->assertions;
        if ($instance->failures) {
            $failed++;
            foreach ($instance->failures as $failure) {
                $failures[] = $label . ' — ' . $failure;
            }
            echo "F  $label\n";
        } else {
            $passed++;
            echo "ok $label\n";
        }
    }
}

echo "\n";
foreach ($failures as $failure) {
    echo "  ✗ $failure\n";
}
if ($failures) {
    echo "\n";
}
printf(
    "%d passed, %d failed, %d assertions\n",
    $passed,
    $failed,
    $assertions
);

exit($failed === 0 ? 0 : 1);
