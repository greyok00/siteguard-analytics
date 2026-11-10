<?php

declare(strict_types=1);

namespace SiteGuard\Core\Store;

/**
 * The owner-saved fingerprint watchlist: a small, human-curated list of
 * named entries, deduped by content id, always capped at 200. Stored as
 * one JSON option row (`siteguard_watchlist`) — tens of entries expected,
 * no table needed.
 */
interface Watchlist
{
    /** @return list<array{id:string,name:string,signals:array<string,string>,rules:list<string>,notes:string,created:int}> the normalized entries, in stored order */
    public function all(): array;

    /**
     * Replaces the whole list (normalize-then-cap happens in the pure
     * layer and the WP adapter). Last-write-wins between concurrent
     * admins is accepted by design; the guard is that every store path
     * normalizes and caps the list it writes, so a stale save can never
     * inject an invalid entry.
     *
     * @param list<array{id:string,name:string,signals:array<string,string>,rules:list<string>,notes:string,created:int}> $entries
     */
    public function save(array $entries): void;
}
