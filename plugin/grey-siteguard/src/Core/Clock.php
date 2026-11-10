<?php
declare(strict_types=1);

namespace SiteGuard\Core;

/**
 * Time source. Fixed windows must be exact under test, and production code
 * should not call time() directly in more than one place.
 */
interface Clock
{
    public function now(): int;
}
