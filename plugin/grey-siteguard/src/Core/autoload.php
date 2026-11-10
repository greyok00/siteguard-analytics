<?php
declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}

// PSR-4 style loader for the SiteGuard\ namespace. No Composer in the shipped
// plugin: shared hosting may not have it, and the tree is small.
spl_autoload_register(static function (string $class): void {
    $prefix = 'SiteGuard\\';
    if (!str_starts_with($class, $prefix)) {
        return;
    }
    $relative = substr($class, strlen($prefix));
    $file = SITEGUARD_DIR . 'src/' . str_replace('\\', '/', $relative) . '.php';
    if (is_readable($file)) {
        require $file;
    }
});
