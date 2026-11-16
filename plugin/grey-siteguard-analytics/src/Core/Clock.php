<?php
declare(strict_types=1);

namespace SiteGuard\Core;





interface Clock
{
    public function now(): int;
}
