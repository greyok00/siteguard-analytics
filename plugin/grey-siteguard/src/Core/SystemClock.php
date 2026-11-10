<?php
declare(strict_types=1);

namespace SiteGuard\Core;

/**
 * Production time source: the unmodified system clock.
 */
final class SystemClock implements Clock
{
    public function now(): int
    {
        return time();
    }
}
