<?php

declare(strict_types=1);

namespace SiteGuard\Core\Profile;

/**
 * The fingerprint watchlist entry model: pure derivation, normalization,
 * import/export, and (from Task 3 on) the matcher that scores owner-saved
 * profiles against live stored fingerprints. An entry anchors ONLY
 * lie-shaped reasons the built-in detectors classify — the closed
 * vocabulary below — never honest raw values, so "matches a saved
 * profile" always means "already looks dishonest to the built-in rules".
 * Enforcement stays outside this class everywhere: matches feed the WAF
 * score, the Gate bar does the denying, and a block still lands on the
 * network address.
 */
final class Watchlist
{
    /** Entries live in one option row; tens expected, never an unbounded crowd. */
    private const ENTRY_CAP = 200;

    /** Shape bounds of the six-key entry (name, rules, signals, notes, created). */
    private const NAME_MAX = 191;
    private const NOTES_MAX = 1000;
    private const SIGNAL_MAX = 7;

    /**
     * The closed anchor vocabulary. Every string the built-in detectors can
     * emit is anchorable; everything else is refused at normalization, so
     * an honest raw value (a bare GPU string, a plain screen size) can
     * never enter the list. Enumerated values, not a pattern: the pair
     * classes are dynamic (`claimed:{f}-stated:{s}`) and a structural
     * check would admit pairs the compatible-overlap law never emits —
     * claimed:mac-stated:ios is an honest iPadOS overlap, claimed:foo-stated:bar
     * is junk that only a forged row would carry. Kept in lockstep with
     * Fingerprint by testAnchorableRulesCarryTheBuiltInLies, which probes
     * the detectors' own outputs against this list.
     *
     * The pair inventory is exactly what Fingerprint::conflicts() can
     * return: claimed and stated must each name a family in its
     * compatible map ({windows, mac, ios, android, linux, chromeos}), the
     * diagonal never disagrees, and the honest overlaps (mac↔ios from
     * iPadOS, android↔linux from Android Chrome) are compatible, so the
     * dynamic pairs are 25: four non-compatible states per claimed family
     * except windows, which contradicts all five others. Plus the two
     * fixed mobile classes. Device-hint reasons are the seven keys of
     * Fingerprint::HIT_SEVERITY verbatim; renderer reasons name the field
     * the software renderer was found in.
     * @var list<string>
     */
    private const ANCHORABLE = [
        // the seven impossible-hint reasons: Fingerprint::HIT_SEVERITY keys, verbatim
        'touchless-ios',
        'desktop-screen-ios',
        'touchless-android',
        'timezone-offset-mismatch',
        'memory-off-scale',
        'cores-implausible',
        'timezone-offset-unparseable',
        // the fixed conflict classes: claimed family and stated mobility contradict
        'claimed:windows-stated:mobile',
        'claimed:ios-stated:desktop',
        // the dynamic conflict pairs, claimed family × stated family
        'claimed:mac-stated:android',
        'claimed:mac-stated:linux',
        'claimed:mac-stated:chromeos',
        'claimed:mac-stated:windows',
        'claimed:ios-stated:android',
        'claimed:ios-stated:linux',
        'claimed:ios-stated:chromeos',
        'claimed:ios-stated:windows',
        'claimed:android-stated:mac',
        'claimed:android-stated:ios',
        'claimed:android-stated:chromeos',
        'claimed:android-stated:windows',
        'claimed:linux-stated:mac',
        'claimed:linux-stated:ios',
        'claimed:linux-stated:chromeos',
        'claimed:linux-stated:windows',
        'claimed:chromeos-stated:mac',
        'claimed:chromeos-stated:ios',
        'claimed:chromeos-stated:android',
        'claimed:chromeos-stated:windows',
        'claimed:windows-stated:mac',
        'claimed:windows-stated:ios',
        'claimed:windows-stated:android',
        'claimed:windows-stated:linux',
        'claimed:windows-stated:chromeos',
        // the software-renderer classes, named for the signal the lie was found in
        'software-rendering:webgl_vendor',
        'software-rendering:webgl_renderer',
    ];

    /**
     * The anchorable reasons, public because Tasks 3–7 build UI phrasing,
     * matcher grading, and POST re-validation on exactly this list.
     * @return list<string>
     */
    public static function ANCHORABLE_RULES(): array
    {
        return self::ANCHORABLE;
    }

    /**
     * One entry per flagged profile. The rules are the union of the
     * built-in detectors over the stored profile (lie reasons only, by
     * construction — a clean profile yields no rules, and so a shape the
     * closed vocabulary refuses); signals carry exactly what the anchored
     * rules depend on, in the normalized form the matcher re-derives from
     * any live profile deterministically: each family key carries the
     * single-field resolution Fingerprint::platform() gives that field
     * alone — the claimed side and the stated side the way conflicts()
     * derives the pair — the mobile flag as '0'/'1', the
     * renderer/vendor strings raw as reported. `created` stays 0 here —
     * the admin action stamps the clock server-side before save; the
     * model layer stays pure and clockless, so the same input always
     * yields the same id.
     * @param array<string,mixed> $profile
     * @return array{id:string,name:string,signals:array<string,string>,rules:list<string>,notes:string,created:int}
     */
    public static function fromProfile(array $profile, string $name, string $notes = ''): array
    {
        $rules = array_values(array_unique(array_merge(
            Fingerprint::impossibles($profile),
            Fingerprint::conflicts($profile),
            Fingerprint::headlessReasons($profile)
        )));
        $signals = [];
        foreach ($rules as $rule) {
            foreach (self::signalsFor($rule, $profile) as $key => $value) {
                $signals[$key] = $value;
            }
        }
        return [
            'id' => self::entryId($signals, $rules),
            'name' => $name,
            'signals' => $signals,
            'rules' => $rules,
            'notes' => $notes,
            'created' => 0,
        ];
    }

    /**
     * The signals one rule depends on. A pair lie pins both of its own
     * sides — the claimed family and the stated family — so a client
     * cannot match while telling a different lie; the fixed mobile classes
     * pin the claimed family plus the mobile flag, which IS the lie's
     * content; a renderer lie pins both WebGL strings, because vendor and
     * renderer travel together ("Google Inc. (SwiftShader)" beside
     * "ANGLE (SwiftShader)") and the matcher compares them
     * case-/whitespace-insensitively — a half-reported anchor would let a
     * client through by leaving the partner string out; both strings are
     * carried whenever the profile reported them, and a side the profile
     * stayed silent on is dropped instead of stored empty.
     * Device-hint lies carry their evidence in the reason string itself
     * (touch/screen/cores/mem/tz shapes), so they depend on no signal
     * key: the detector re-runs on the live profile. Rules outside the
     * vocabulary can only arrive from a forged row — normalization is the
     * gate it never gets past — and the model refuses to guess what they
     * would depend on.
     * @param array<string,mixed> $profile
     * @return array<string,string>
     */
    private static function signalsFor(string $rule, array $profile): array
    {
        if (!in_array($rule, self::ANCHORABLE, true)) {
            return [];
        }
        if (str_starts_with($rule, 'claimed:')) {
            return self::pairSignals($rule);
        }
        if (str_starts_with($rule, 'software-rendering:')) {
            return array_filter([
                'webgl_vendor' => self::raw($profile, 'webgl_vendor'),
                'webgl_renderer' => self::raw($profile, 'webgl_renderer'),
            ], static fn (string $value): bool => $value !== '');
        }
        // the seven impossible-hint reasons: self-describing
        return [];
    }

    /**
     * Which sides a pair lie named. The fixed mobile classes are
     * self-describing (mobile versus desktop IS the stated side); the
     * dynamic pairs read the families out of the pair string, which
     * Fingerprint::conflicts() built from the live profile in the first
     * place — every vocabulary pair names real families, never empty.
     * @return array<string,string>
     */
    private static function pairSignals(string $rule): array
    {
        if ($rule === 'claimed:windows-stated:mobile') {
            return ['platform' => 'windows', 'ua_mobile' => '1'];
        }
        if ($rule === 'claimed:ios-stated:desktop') {
            return ['platform' => 'ios', 'ua_mobile' => '0'];
        }
        $pair = explode('-stated:', substr($rule, strlen('claimed:')), 2);
        return ['platform' => $pair[0], 'ua_platform' => $pair[1] ?? ''];
    }

    /**
     * The entry id: first 12 hex of the sha256 content digest. Name and
     * notes are deliberately not in the hash — renaming keeps the id (one
     * attacker = one entry) and identical anchors imported twice collapse
     * to one id. Rules sort above signals, each set sorted independently,
     * so detector emission order can never change an id.
     * detector emission order can never change an id.
     * @param array<string,string> $signals
     * @param list<string> $rules
     */
    public static function entryId(array $signals, array $rules): string
    {
        $material = self::sortedRules($rules) . "\n" . self::sortedSignals($signals);
        return substr(hash('sha256', $material), 0, 12);
    }

    /**
     * The shape gate for everything stored or imported: valid entries pass
     * through with the id recomputed from content (a forged id cannot
     * survive), everything else is refused with null — never fatal, never
     * repaired by guessing. Valid shape: exactly the six keys; name
     * non-empty ≤191 chars; rules a non-empty list ⊆ the anchorable
     * vocabulary (duplicates collapse); signals string-keyed string
     * values of real (non-whitespace) values, ≤7 keys, and keys drawn
     * from Fingerprint::SIGNALS alone (the key set is closed like the
     * rule vocabulary — an unknown key could never be re-derived live, so
     * it would make the entry permanently unmatchable); notes ≤1000
     * chars; created an int ≥0.
     * @return array{id:string,name:string,signals:array<string,string>,rules:list<string>,notes:string,created:int}|null
     */
    public static function normalizeEntry(mixed $raw): ?array
    {
        if (!is_array($raw) || count($raw) !== 6 || !isset(
            $raw['id'],
            $raw['name'],
            $raw['signals'],
            $raw['rules'],
            $raw['notes'],
            $raw['created']
        )) {
            return null;
        }
        $name = is_string($raw['name']) ? trim($raw['name']) : '';
        if ($name === '' || self::length($name) > self::NAME_MAX) {
            return null;
        }
        $rules = $raw['rules'];
        if (!is_array($rules) || $rules === [] || !array_is_list($rules)) {
            return null;
        }
        $rules = array_values(array_unique($rules));
        foreach ($rules as $rule) {
            if (!is_string($rule) || !in_array($rule, self::ANCHORABLE, true)) {
                return null;
            }
        }
        $signals = $raw['signals'];
        if (!is_array($signals) || count($signals) > self::SIGNAL_MAX) {
            return null;
        }
        foreach ($signals as $key => $value) {
            if (!is_string($key) || !is_string($value) || trim($value) === ''
                || !in_array($key, Fingerprint::SIGNALS, true)) {
                return null;
            }
        }
        $notes = $raw['notes'];
        if (!is_string($notes) || self::length($notes) > self::NOTES_MAX) {
            return null;
        }
        $created = $raw['created'];
        if (!is_int($created) || $created < 0) {
            return null;
        }
        return [
            'id' => self::entryId($signals, $rules),
            'name' => $name,
            'signals' => $signals,
            'rules' => $rules,
            'notes' => $notes,
            'created' => $created,
        ];
    }

    /**
     * Imports merge by id with imported-wins (the freshest view of the
     * same anchors): a colliding id is replaced in place at its current
     * position, new imports append after the current list, and the whole
     * merges stays under the 200-entry cap. Deduping by CONTENT id is the
     * whole law — the identical profile imported from two installs is one
     * attacker, even when the owners named it differently, because the
     * ids agree and one row is dropped.
     * @param list<array> $current normalized entries, in stored order
     * @param list<array> $imported normalized entries, in payload order
     * @return list<array> the merged, capped list
     */
    public static function mergeImport(array $current, array $imported): array
    {
        $importedById = [];
        foreach ($imported as $entry) {
            if (!is_array($entry) || !is_string($entry['id'] ?? null) || $entry['id'] === '') {
                continue;
            }
            $importedById[$entry['id']] = $entry;
        }
        $merged = [];
        $seen = [];
        foreach ($current as $entry) {
            if (!is_array($entry) || !is_string($entry['id'] ?? null) || $entry['id'] === ''
                || isset($seen[$entry['id']])) {
                continue;
            }
            $seen[$entry['id']] = true;
            // imported wins: a colliding id renders the imported row here
            $merged[] = $importedById[$entry['id']] ?? $entry;
        }
        foreach ($importedById as $id => $entry) {
            if (!isset($seen[$id])) {
                $seen[$id] = true;
                $merged[] = $entry;
            }
        }
        return array_slice($merged, 0, self::ENTRY_CAP);
    }

    /**
     * Removes one entry by id, preserving the order of the survivors.
     * Rows that are not entries (junk a buggy upstream let through) carry
     * no valid id, so they stay: the store's normalize-at-save drops them
     * next time anything is written. Never fatal.
     * @param list<array> $entries
     * @return list<array>
     */
    public static function without(array $entries, string $id): array
    {
        return array_values(array_filter($entries,
            static fn (array $entry): bool => ($entry['id'] ?? null) !== $id));
    }

    /**
     * The export envelope. `exported` is UTC ISO8601 so the file names its
     * own moment in one unambiguous zone; the entries go out unchanged —
     * import re-derives every id from content anyway.
     * @param list<array> $entries
     * @return array{version:int,exported:string,entries:list<array>}
     */
    public static function exportPayload(array $entries): array
    {
        return [
            'version' => 1,
            'exported' => gmdate(DATE_ATOM),
            'entries' => $entries,
        ];
    }

    /**
     * One matching entry emits exactly one hit, the same shape
     * Fingerprint::hits returns — Task 4 feeds these straight into the
     * score mix the built-in device-hint hits use. Implemented in Task 3
     * (the matcher with its graded severity table); the Task-2 model
     * carries the empty placeholder so Tasks 3–7 can wire against a
     * stable signature.
     * @param array<string,mixed> $profile
     * @param list<array{id:string,name:string,signals:array<string,string>,rules:list<string>,notes:string,created:int}> $entries
     * @return list<array{rule:string,group:string,severity:int,evidence:array}>
     */
    public static function hits(array $profile, array $entries): array
    {
        return [];
    }

    // ------------------------------------------------------------ internals

    /**
     * The stored form of a raw reported string. Beacon values are strings
     * by collection, so an int/float/array here is a corrupt or forged
     * row, not a variant — read as silence (empty string). Trims, because
     * Task 3 matches renderer/vendor case- and whitespace-insensitively
     * and the entry must normalize the same way to agree with itself.
     * @param array<string,mixed> $profile
     */
    private static function raw(array $profile, string $key): string
    {
        $value = $profile[$key] ?? '';
        if (!is_string($value)) {
            return '';
        }
        return trim($value);
    }

    /**
     * The id material, one rule per line under a section tag. Only string
     * rules hash: anything else is junk the validators above already
     * refuse, so the hash stays warningless even when called directly.
     */
    private static function sortedRules(array $rules): string
    {
        $rules = array_values(array_filter($rules, 'is_string'));
        $rules = array_values(array_unique($rules));
        sort($rules, SORT_STRING);
        $lines = ['$rules'];
        foreach ($rules as $rule) {
            $lines[] = $rule;
        }
        return implode("\n", $lines);
    }

    /**
     * The id material, one key=value line per signal under a section tag,
     * keys sorted. Only string keys and values hash — partial or corrupt
     * arrays hash to their honest subset instead of warning.
     */
    private static function sortedSignals(array $signals): string
    {
        $lines = ['$signals'];
        $keys = array_keys($signals);
        $stringKeys = array_values(array_filter($keys, 'is_string'));
        sort($stringKeys, SORT_STRING);
        foreach ($stringKeys as $key) {
            if (!is_string($signals[$key])) {
                continue;
            }
            $lines[] = $key . '=' . $signals[$key];
        }
        return implode("\n", $lines);
    }

    /**
     * Byte length. Names are owner-typed, not attacker-supplied, and
     * every other length check in this codebase is byte-based (strlen, no
     * mb_* dependency), so the caps count the same way.
     */
    private static function length(string $value): int
    {
        return strlen($value);
    }
}
