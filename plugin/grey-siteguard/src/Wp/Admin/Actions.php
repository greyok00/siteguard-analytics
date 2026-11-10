<?php
declare(strict_types=1);

namespace SiteGuard\Wp\Admin;

use SiteGuard\Core\Crypto;
use SiteGuard\Core\Ip;
use SiteGuard\Core\Profile\Fingerprint;
use SiteGuard\Core\Profile\Watchlist as WatchlistLogic;
use SiteGuard\Core\Settings;
use SiteGuard\Core\Subjects;
use SiteGuard\Wp\Caps;
use SiteGuard\Wp\Config;
use SiteGuard\Wp\Export;
use SiteGuard\Wp\Store\WpdbAuditStore;
use SiteGuard\Wp\Store\WpdbWatchlist;

/**
 * admin-post handlers. Each one: capability check, nonce check, validate,
 * act, audit, redirect. A missing check here would be an authorization bug,
 * so the four steps are written out rather than abstracted.
 *
 * The watchlist handlers (Task 7 renders their forms) follow the same four
 * steps and add an honesty law the other handlers cannot need: an entry's
 * content comes only from the server re-deriving it — from a stored visitor
 * profile or through the anchor gate rebuilt with fromProfile — never from
 * the client's word about ids, rules, or signals. An honest raw value can
 * never enter the watchlist via POST; normalization at the store refuses
 * everything the gate misses.
 */
final class Actions
{
    /** Uploaded import files are read only up to this size; larger is refused before reading. */
    private const IMPORT_MAX_BYTES = 262144;

    /** The 200-entry watchlist cap, mirrored from the private model/adapter consts; the WatchlistTest flood probe is the drift guard. */
    private const WATCHLIST_CAP = 200;

    /** Per-viewer candidate dismissals cap; the click list stays small and the newest always wins. */
    private const DISCARD_CAP = 100;

    /** The user-meta key the discard handler writes and the card reads. */
    private const DISCARD_META = 'siteguard_wl_dismissed';

    public static function boot(): void
    {
        add_action('admin_post_siteguard_settings', [self::class, 'saveSettings']);
        add_action('admin_post_siteguard_block', [self::class, 'block']);
        add_action('admin_post_siteguard_lift', [self::class, 'lift']);
        add_action('admin_post_siteguard_emergency', [self::class, 'emergency']);
        add_action('admin_post_siteguard_export', [self::class, 'export']);
        add_action('admin_post_siteguard_export_bundle', [self::class, 'exportBundle']);
        add_action('admin_post_siteguard_watchlist_save', [self::class, 'watchlistSave']);
        add_action('admin_post_siteguard_watchlist_delete', [self::class, 'watchlistDelete']);
        add_action('admin_post_siteguard_watchlist_discard', [self::class, 'watchlistDiscard']);
        add_action('admin_post_siteguard_watchlist_import', [self::class, 'watchlistImport']);
        add_action('admin_post_siteguard_watchlist_export', [self::class, 'watchlistExport']);
    }

    public static function saveSettings(): void
    {
        self::requireCap(Caps::MANAGE_SETTINGS);
        check_admin_referer('siteguard_settings');

        $input = wp_unslash($_POST);
        unset($input['action'], $input['_wpnonce'], $input['_wp_http_referer'], $input['submit']);
        [$clean, $errors] = Settings::sanitize((array) $input);

        if ($errors) {
            Menu::redirect(Menu::SETTINGS, implode('; ', $errors), 'error');
        }

        update_option(Settings::OPTION, $clean);
        Config::forget();
        delete_transient(WafProbe::cacheKey());
        delete_transient('siteguard_collector_probe');
        self::audit('settings.saved', 'settings', ['profile' => $clean['profile'], 'waf_profile' => $clean['waf_profile']]);
        Menu::redirect(Menu::SETTINGS, 'Settings saved.');
    }

    public static function block(): void
    {
        self::requireCap(Caps::MANAGE_BLOCKS);
        check_admin_referer('siteguard_block');

        $raw = trim(sanitize_text_field(wp_unslash((string) ($_POST['subject'] ?? ''))));
        $hours = max(1, min(168, absint(wp_unslash($_POST['hours'] ?? 1))));
        $reason = substr(sanitize_text_field(wp_unslash((string) ($_POST['reason'] ?? ''))), 0, 191);

        $subject = self::normaliseSubject($raw);
        if ($subject === null) {
            Menu::redirect(Menu::SECURITY, 'That address or visitor id is not valid.', 'error');
        }

        $now = time();
        $scope = str_starts_with($subject, Subjects::ACCOUNT_PREFIX)
            ? 'account'
            : (str_starts_with($subject, Subjects::VISITOR_PREFIX) ? 'visitor' : 'ip');

        $id = Config::blocks()->add(
            $subject,
            $scope,
            $reason !== '' ? $reason : 'manual block',
            'manual',
            ['by' => get_current_user_id()],
            $now,
            $now + $hours * 3600,
            'admin:' . get_current_user_id()
        );

        self::audit('block.created', $subject, ['hours' => $hours, 'block_id' => $id]);
        Menu::redirect(
            Menu::SECURITY,
            $id > 0 ? 'Block applied.' : 'That subject already has an active block.'
        );
    }

    public static function lift(): void
    {
        self::requireCap(Caps::MANAGE_BLOCKS);
        check_admin_referer('siteguard_lift');

        $subject = self::normaliseSubject(trim(sanitize_text_field(wp_unslash((string) ($_POST['subject'] ?? '')))));
        if ($subject === null) {
            Menu::redirect(Menu::SECURITY, 'That subject is not valid.', 'error');
        }

        $lifted = Config::blocks()->lift($subject, time());
        self::audit('block.lifted', $subject, ['lifted' => $lifted]);
        Menu::redirect(Menu::SECURITY, $lifted ? 'Block lifted.' : 'No active block for that subject.');
    }

    public static function emergency(): void
    {
        self::requireCap(Caps::MANAGE_SETTINGS);
        check_admin_referer('siteguard_emergency');

        $enabled = sanitize_key(wp_unslash((string) ($_POST['enabled'] ?? '0'))) === '1';
        update_option('siteguard_emergency_off', $enabled, false);
        self::audit($enabled ? 'protection.stopped' : 'protection.resumed', 'emergency', []);
        Menu::redirect(
            Menu::OPERATIONS,
            $enabled ? 'Protection stopped.' : 'Protection resumed.'
        );
    }

    public static function export(): void
    {
        self::requireCap(Caps::EXPORT_DATA);
        check_admin_referer('siteguard_export');

        $type = sanitize_key((string) ($_GET['type'] ?? ''));
        self::audit('data.exported', $type, []);
        Export::stream($type);
    }

    /**
     * One file holding every table, for analysis outside WordPress. The
     * plugin never sends this anywhere; the owner downloads it and decides.
     */
    public static function exportBundle(): void
    {
        self::requireCap(Caps::EXPORT_DATA);
        check_admin_referer('siteguard_export');

        self::audit('data.exported', 'bundle', []);
        Export::streamBundle();
    }

    /**
     * Upsert one entry by content id. The content comes from the server:
     * either a stored visitor's profile re-derived fresh through the model,
     * or the blank form's anchor payload rebuilt through the anchor gate.
     * Normalization at the store is the second gate; re-derivation is the
     * first, and it is where an honest value is refused.
     */
    public static function watchlistSave(): void
    {
        self::requireCap(Caps::MANAGE_BLOCKS);
        check_admin_referer('siteguard_watchlist_save');

        $name = sanitize_text_field(wp_unslash((string) ($_POST['name'] ?? '')));
        if ($name === '' || strlen($name) > 191) {
            // 191 is the model's byte-based name cap; refusing here gives the
            // owner a redirect instead of a store that silently drops the row.
            Menu::redirect(Menu::PROFILES, 'The profile needs a name.', 'error');
        }
        $notes = trim(sanitize_textarea_field(wp_unslash((string) ($_POST['notes'] ?? ''))));
        if (strlen($notes) > 1000) {
            // The model's byte-based notes cap (NOTES_MAX). Without this
            // guard the over-long notes sailed to normalization, which
            // refused the WHOLE entry under the anchor message — naming no
            // lie the check failed on. The honest redirect names the limit.
            Menu::redirect(Menu::PROFILES, 'Notes are limited to 1000 characters.', 'error');
        }

        // validate the content source. The entry is always re-derived
        // server-side — from a stored visitor's profile, or through the
        // anchor gate — never from the client's word about ids, rules, or
        // signals, so an honest value can never enter via POST.
        $visitorId = trim(sanitize_text_field(wp_unslash((string) ($_POST['visitor_id'] ?? ''))));
        if ($visitorId !== '') {
            if (!Crypto::isId($visitorId)) {
                Menu::redirect(Menu::PROFILES, 'That visitor id is not valid.', 'error');
            }
            // The visitor-exists check matters: profileFor() answers silence
            // ([] — clean, never a lie) both for an unknown id and a visitor
            // that never beaconed, so fromProfile on it would produce the
            // ruleless entry normalization refuses — with the wrong message.
            $profile = Config::people()->profileFor($visitorId);
            if ($profile === []) {
                Menu::redirect(Menu::PROFILES, 'That visitor id is not known.', 'error');
            }
            if (WatchlistLogic::fromProfile($profile, '', '')['rules'] === []) {
                Menu::redirect(Menu::PROFILES,
                    'That visitor tells no lie the watchlist can anchor.', 'error');
            }
            $entry = WatchlistLogic::fromProfile($profile, $name, $notes);
        } else {
            $anchors = wp_unslash($_POST['anchors'] ?? null);
            $entry = self::anchorEntry(
                is_array($anchors) ? array_values(array_filter($anchors, 'is_array')) : [],
                $name,
                $notes
            );
        }
        if ($entry === null || WatchlistLogic::normalizeEntry($entry) === null) {
            Menu::redirect(Menu::PROFILES, 'No anchorable reasons in that submission.', 'error');
        }

        // Upsert by content id, the placement law mergeImport pins: a
        // colliding id is replaced in place (a rename keeps the row where
        // the owner saw it), a new id appends after the list.
        $entry['created'] = time(); // controller ruling: the action stamps the clock server-side
        $store = new WpdbWatchlist();
        $before = $store->all();
        $kept = [];
        $updated = false;
        foreach ($before as $existing) {
            if (!$updated && ($existing['id'] ?? null) === $entry['id']) {
                $updated = true;
                $kept[] = $entry;
                continue;
            }
            $kept[] = $existing;
        }
        if (!$updated) {
            if (count($kept) >= self::WATCHLIST_CAP) {
                // the store caps by keeping the FIRST 200: appending a new
                // entry to a full list would slice it straight back off, so
                // the honest answer is a refusal, never a silent no-op.
                Menu::redirect(Menu::PROFILES,
                    'The watchlist is full (200 entries): remove one first.', 'error');
            }
            $kept[] = $entry;
        }
        $store->save($kept);

        self::audit('watchlist.saved', $entry['id'], ['id' => $entry['id'], 'name' => $entry['name']]);
        Menu::redirect(Menu::PROFILES, $updated ? 'Watchlist profile updated.' : 'Watchlist profile saved.');
    }

    public static function watchlistDelete(): void
    {
        self::requireCap(Caps::MANAGE_BLOCKS);
        check_admin_referer('siteguard_watchlist_delete');

        $id = sanitize_text_field(wp_unslash((string) ($_POST['id'] ?? '')));
        if ($id === '') {
            Menu::redirect(Menu::PROFILES, 'No watchlist entry named.', 'error');
        }

        $store = new WpdbWatchlist();
        $before = $store->all();
        $kept = WatchlistLogic::without($before, $id);
        $existed = count($kept) !== count($before);
        if ($existed) {
            // rider from Task 6's review: a no-op id must not rewrite the
            // option — the save write happens only behind a real removal, so
            // a stray POST naming nothing touches exactly nothing.
            $store->save($kept);
        }
        self::audit('watchlist.removed', $id, ['removed' => $existed]);
        Menu::redirect(Menu::PROFILES, $existed ? 'Watchlist entry removed.' : 'No watchlist entry with that id.',
            $existed ? 'success' : 'error');
    }

    /**
     * The candidates card's per-browser Discard: one visitor id hidden in
     * the viewer's user-meta dismissal list — never the watchlist, never
     * any shared option, never persisted anywhere else. The stored cap is
     * the list's own hygiene (the visitors prune makes ids stale in 30
     * days anyway); a full list drops the OLDEST dismissal so the newest
     * click always takes effect. The id is validated by shape before it is
     * written anywhere; an unknown-visitor POST stores the id anyway — the
     * card only ever reads ids its own rows carried, so a forged one is a
     * harmless no-op hiding nothing that was not already hidden.
     */
    public static function watchlistDiscard(): void
    {
        self::requireCap(Caps::MANAGE_BLOCKS);
        check_admin_referer('siteguard_watchlist_discard');

        $visitorId = sanitize_text_field(wp_unslash((string) ($_POST['visitor'] ?? '')));
        if (!Crypto::isId($visitorId)) {
            Menu::redirect(Menu::PROFILES, 'That visitor id is not valid.', 'error');
        }
        $dismissed = self::dismissals((int) get_current_user_id());
        if (!in_array($visitorId, $dismissed, true)) {
            $dismissed[] = $visitorId;
            if (count($dismissed) > self::DISCARD_CAP) {
                $dismissed = array_slice($dismissed, -self::DISCARD_CAP);
            }
            update_user_meta((int) get_current_user_id(), self::DISCARD_META, $dismissed);
        }
        Menu::redirect(Menu::PROFILES, 'Candidate hidden: it stays hidden for you only, and returns if it beacons again.');
    }

    /**
     * The viewer's dismissal list, shape-guarded (junk reads as empty).
     * Public because the candidates card filters its own rows with it —
     * the read side of the same per-browser verb.
     * @return list<string>
     */
    public static function dismissals(int $userId): array
    {
        $raw = get_user_meta($userId, self::DISCARD_META, true);
        if (!is_array($raw)) {
            return [];
        }
        $out = [];
        foreach ($raw as $id) {
            if (is_string($id) && Crypto::isId($id)) {
                $out[] = $id;
            }
        }
        return $out;
    }

    /**
     * Entries arrive as JSON: an uploaded file (size-checked BEFORE reading
     * — the cap exists so a hostile upload cannot make the handler parse an
     * arbitrary blob) or a pasted textarea. Every row runs through the same
     * normalizeEntry gate the store applies; invalid rows are dropped with
     * a count in the notice, never fatal.
     */
    public static function watchlistImport(): void
    {
        self::requireCap(Caps::MANAGE_BLOCKS);
        check_admin_referer('siteguard_watchlist_import');

        $tmp = (string) ($_FILES['file']['tmp_name'] ?? '');
        $json = '';
        if ($tmp !== '' && is_uploaded_file($tmp)) {
            if ((int) filesize($tmp) > self::IMPORT_MAX_BYTES) {
                Menu::redirect(Menu::PROFILES, 'That file is larger than 256KB.', 'error');
            }
            $json = (string) file_get_contents($tmp);
        } else {
            $json = trim(sanitize_textarea_field(wp_unslash((string) ($_POST['payload'] ?? ''))));
        }
        if ($json === '') {
            Menu::redirect(Menu::PROFILES, 'Nothing to import: choose a file or paste an export.', 'error');
        }

        $decoded = json_decode($json, true);
        if (!is_array($decoded) || !is_array($decoded['entries'] ?? null)) {
            Menu::redirect(Menu::PROFILES, 'That payload is not a SiteGuard watchlist export.', 'error');
        }

        $kept = [];
        $dropped = 0;
        foreach ($decoded['entries'] as $candidate) {
            $entry = WatchlistLogic::normalizeEntry($candidate);
            if ($entry === null) {
                $dropped++;
                continue;
            }
            $kept[] = $entry;
        }
        $store = new WpdbWatchlist();
        // rider from Task 6's review: the notice and audit report the
        // REALIZED delta — what the saved list actually gained — instead of
        // the normalizer-survivor count, which overstates when the merged
        // rows replace saved ids in place (imported wins) or the 200-cap
        // slice refuses the append. The store re-reads the option on every
        // all(), so both counts measure the option truthfully.
        $before = count($store->all());
        $store->save(WatchlistLogic::mergeImport($store->all(), $kept));
        $after = count($store->all());
        $realized = max(0, $after - $before);

        self::audit('watchlist.imported', 'watchlist',
            ['added' => $realized, 'dropped' => $dropped]);
        Menu::redirect(Menu::PROFILES, self::importNotice(count($kept), $dropped, $realized));
    }

    /**
     * The export file. Same streaming precedent Export::streamBundle sets:
     * JSON attachment headers, a UTC-stamped filename, Content-Length, exit
     * after echoing. The content is only what the store holds.
     */
    public static function watchlistExport(): void
    {
        self::requireCap(Caps::EXPORT_DATA);
        check_admin_referer('siteguard_watchlist_export');

        $json = wp_json_encode(WatchlistLogic::exportPayload((new WpdbWatchlist())->all()));
        if (!is_string($json)) {
            wp_die(esc_html('The export could not be encoded.'), '', ['response' => 500]);
        }

        self::audit('watchlist.exported', 'watchlist', ['bytes' => strlen($json)]);
        nocache_headers();
        header('Content-Type: application/json; charset=utf-8');
        header('Content-Disposition: attachment; filename="siteguard-watchlist-' . gmdate('Ymd-His') . '.json"');
        header('Content-Length: ' . strlen($json));
        header('X-Content-Type-Options: nosniff');
        echo $json;
        exit;
    }

    /**
     * THE HONEST-LAW GATE. Refuses a submission that: names no anchor,
     * names a rule outside ANCHORABLE_RULES(), or names a rule that does
     * not re-derive when fromProfile runs over the values the payload
     * actually carried (every checked lie must fire on those values — a
     * fixed value that contradicts another anchor's is the usual cause).
     * The entry's signals are re-derived from those values by
     * fromProfile/entryId, so a forged per-anchor id or an unknown signal
     * key rides as silence, never into the stored entry. What survives is
     * exactly the model's own derivation — never the client's word.
     *
     * @param array<mixed> $anchors
     * @return array{id:string,name:string,signals:array<string,string>,rules:list<string>,notes:string,created:int}|null
     */
    public static function anchorEntry(array $anchors, string $name, string $notes): ?array
    {
        $vocabulary = WatchlistLogic::ANCHORABLE_RULES();
        $postable = Fingerprint::SIGNALS;
        $profile = [];
        $requested = [];
        foreach ($anchors as $anchor) {
            if (!is_array($anchor) || !is_string($anchor['rule'] ?? null)) {
                continue;
            }
            $rule = $anchor['rule'];
            if (!in_array($rule, $vocabulary, true)) {
                return null; // not an anchorable lie: the payload does not enter
            }
            $requested[$rule] = true;
            $signals = $anchor['signals'] ?? null;
            if (!is_array($signals)) {
                continue;
            }
            foreach ($signals as $key => $value) {
                if (is_string($key) && is_string($value)
                    && (in_array($key, $postable, true) || in_array($key, Fingerprint::DEVICE_HINTS, true))) {
                    // rider from Task 6's review: each raw POST value passes
                    // the sanitizer before re-derivation (keys are already
                    // whitelisted by the check above). The function_exists
                    // guard keeps the gate unit-callable under the test
                    // runner, which loads no WordPress shim; live WordPress
                    // always sanitizes. The handler unslashes anchors before
                    // this runs, so no slash stripping is owed here.
                    $profile[$key] = function_exists('sanitize_text_field')
                        ? sanitize_text_field($value)
                        : $value; // the fixed value the detectors re-fire on
                }
                // else: unknown or non-string key/value — ignored (silence, not trust)
            }
        }
        if ($requested === []) {
            return null; // no anchor named, nothing re-derived: refuse.
        }
        $entry = WatchlistLogic::fromProfile($profile, $name, $notes);
        if (array_diff(array_keys($requested), $entry['rules']) !== []) {
            return null; // a checked lie the carried values do not fire: refuse.
            // An honest value can never enter via POST.
        }
        return $entry;
    }

    /**
     * The import notice. $realized is the measured store delta (added rows),
     * never the survivor count: below the survivor number it means saved ids
     * were replaced in place, or a full list sliced the append off — the
     * short sentence says which way the store really moved.
     */
    private static function importNotice(int $kept, int $dropped, int $realized): string
    {
        if ($kept === 0) {
            return 'No valid entries in that payload'
                . ($dropped > 0 ? ' (' . $dropped . ' dropped as invalid).' : '.');
        }
        $base = 'Imported ' . $kept . ' watchlist ' . ($kept === 1 ? 'entry' : 'entries');
        if ($realized < $kept) {
            $base .= '; the saved list gained ' . $realized . ' '
                . ($realized === 1 ? 'entry' : 'entries');
        }
        return $base . ($dropped > 0 ? '; ' . $dropped . ' dropped as invalid.' : '.');
    }

    private static function requireCap(string $capability): void
    {
        if (!Caps::userCan($capability)) {
            wp_die(esc_html('You do not have permission to do that.'), 403);
        }
    }

    private static function audit(string $action, string $target, array $details): void
    {
        (new WpdbAuditStore($GLOBALS['wpdb']))->record(
            (int) get_current_user_id(),
            $action,
            $target,
            $details,
            time()
        );
    }

    /** Accepts an address or an existing subject/visitor id. */
    private static function normaliseSubject(string $raw): ?string
    {
        if ($raw === '') {
            return null;
        }
        if (str_starts_with($raw, Subjects::ACCOUNT_PREFIX)) {
            $id = (int) substr($raw, 2);
            return $id > 0 ? Subjects::account($id) : null;
        }
        if (str_starts_with($raw, Subjects::VISITOR_PREFIX)) {
            $id = substr($raw, 2);
            return Crypto::isId($id) ? Subjects::visitor($id) : null;
        }
        if (str_starts_with($raw, 'ip4:') || str_starts_with($raw, 'ip6:')) {
            return substr($raw, 0, 48);
        }
        if (Crypto::isId($raw)) {
            return Subjects::visitor($raw);
        }
        $ip = Ip::normalize($raw);
        return $ip === null ? null : Subjects::ip(Ip::subject($ip));
    }
}
