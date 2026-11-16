<?php
declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}



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
