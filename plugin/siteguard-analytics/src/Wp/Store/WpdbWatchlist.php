<?php

declare(strict_types=1);

namespace SiteGuard\Wp\Store;

use SiteGuard\Core\Profile\Watchlist as WatchlistLogic;
use SiteGuard\Core\Store\Watchlist;

/**
 * The option-backed owner watchlist. The whole list lives in ONE option row
 * — no table, no wpdb — because the design caps it at 200 small rows and
 * tens are actually expected, so a single read serves every request that
 * enforces the watchlist.
 *
 * Every path normalizes on BOTH ends (the stale-save guard): save()
 * normalizes and caps before writing, and all() re-normalizes what it
 * finds. Writers of the option are admin handlers a version apart, and
 * last-write-wins between concurrent admins is accepted by design — the
 * guard the design asks of us is narrower: no store path can ever WRITE
 * an invalid entry or break the 200 cap, so a stale save degrades to an
 * older-but-valid list, never to a corrupt one. Reading normalizes too,
 * so a row already sitting in the option from an older plugin version, a
 * hand-edited database, or a partially failed write can never reach the
 * Gate in a shape the matcher would misread — it is dropped instead.
 */
final class WpdbWatchlist implements Watchlist
{
    /** The one option row; kept private because clients go through this store, never around it. */
    private const OPTION = 'siteguard_watchlist';

    /** Mirrors WatchlistLogic::ENTRY_CAP (its const is private): a stale save must not widen this file's cap when the model moves. */
    private const ENTRY_CAP = 200;

    /**
     * A corrupt row is dropped, never kept, never repaired, never thrown
     * at: normalization refuses it by shape or content (unknown rule
     * strings, unknown signal keys, a forged id), the adapter cannot guess
     * what it meant, and keeping one would hand the Gate a row the matcher
     * could read silently wrong — while throwing would fatal the Gate on
     * owner data. A corrupted option must never take the site's protection
     * down with it.
     */
    public function all(): array
    {
        $raw = get_option(self::OPTION, false);
        if (!is_array($raw)) {
            // missing option (false), a serialized non-array, or truncated
            // JSON: all read as an empty watchlist, not an error
            return [];
        }
        $entries = [];
        foreach ($raw as $row) {
            $entry = WatchlistLogic::normalizeEntry($row);
            if ($entry !== null) {
                $entries[] = $entry;
            }
        }
        return $entries;
    }

    /**
     * The cap is enforced here, at every write — not only in the pure
     * layer's mergeImport — because this store is also written by the
     * save/upsert/delete flows that never call the merge: no store path
     * can ever write past the cap, so a stale save cannot smuggle an
     * oversized list past the model. 200 equals the pure layer's private
     * ENTRY_CAP, pinned by the model's merge tests.
     */
    public function save(array $entries): void
    {
        $kept = [];
        foreach ($entries as $entry) {
            $normalized = WatchlistLogic::normalizeEntry($entry);
            if ($normalized !== null) {
                $kept[] = $normalized;
            }
        }
        $kept = array_slice($kept, 0, self::ENTRY_CAP, false);
        // autoload false: the list is only read when enforcement asks for
        // it (the Gate, the admin cards) — not on every page render
        update_option(self::OPTION, array_values($kept), false);
    }
}
