<?php

declare(strict_types=1);

namespace SiteGuard\Tests;

/**
 * Schema pins for the candidates-attribution seam (final-review Finding 1):
 * the visitors rollup carries the beacon's keyed address hash with the
 * exact column shape the sessions table declares, a schema-version bump
 * keeps existing installs on the dbDelta path, and the People store writes
 * the hash through touchVisitor the way touchSession already does. The
 * Wp layer has no render/store runner harness (house boundary), so these
 * are source-level pins the same way SettingsTest pins the settings form.
 */
final class InstallerTest extends TestCase
{
    /** The one declared shape both attribution tables must share. */
    private const IP_HASH_DECLARATION = "ip_hash char(40) NOT NULL DEFAULT ''";

    /** @return array<string,string> table name => extracted CREATE body */
    private static function createBodies(): array
    {
        static $bodies = null;
        if ($bodies !== null) {
            return $bodies;
        }
        $source = (string) file_get_contents(SITEGUARD_DIR . 'src/Wp/Installer.php');
        $bodies = [];
        foreach (['sessions', 'visitors'] as $table) {
            $start = strpos($source, "CREATE TABLE {\$t['{$table}']} ");
            $stop = $start === false ? false : strpos($source, ') $charset;', $start);
            $bodies[$table] = ($start !== false && $stop !== false)
                ? (string) substr($source, $start, $stop - $start)
                : '';
        }
        return $bodies;
    }

    public function testVisitorSchemaCarriesTheBeaconHashInParityWithSessions(): void
    {
        $bodies = self::createBodies();
        $this->assertTrue($bodies['sessions'] !== '', 'The sessions CREATE body must be extractable.');
        $this->assertTrue($bodies['visitors'] !== '', 'The visitors CREATE body must be extractable.');

        $this->assertTrue(str_contains($bodies['visitors'], self::IP_HASH_DECLARATION),
            'The visitors rollup declares the keyed address hash the candidates card attributes with.');
        $this->assertTrue(str_contains($bodies['sessions'], self::IP_HASH_DECLARATION),
            'The sessions table keeps its own hash declaration.');

        preg_match("~ip_hash [\w()]+ NOT NULL DEFAULT ''~", $bodies['visitors'], $visitorDecl);
        preg_match("~ip_hash [\w()]+ NOT NULL DEFAULT ''~", $bodies['sessions'], $sessionDecl);
        $this->assertSame($sessionDecl[0] ?? '', $visitorDecl[0] ?? '',
            'sessions.ip_hash and visitors.ip_hash are declared with the identical type and length.');

        $this->assertFalse(str_contains($bodies['visitors'], 'device varchar'),
            'Device and browser classes stay on events/sessions rows; the visitor rollup stays lean.');
        $this->assertFalse(str_contains($bodies['visitors'], 'browser varchar'),
            'Device and browser classes stay on events/sessions rows; the visitor rollup stays lean.');
    }

    public function testSchemaVersionBumpKeepsExistingInstallsOnTheDbDeltaPath(): void
    {
        // The visitors ip_hash column rides dbDelta on an existing install
        // only when the stored version compares LOWER than the current one:
        // install() compares the stored option against this constant. The
        // in-house 0.1.6 move (0.1.x: tables gain columns in place) bumps
        // exactly this constant; the pin demands the bump to above 2.
        $plugin = (string) file_get_contents(SITEGUARD_DIR . 'grey-siteguard.php');
        preg_match("/define\('SITEGUARD_TABLE_VERSION', '(\d+)'\);/", $plugin, $m);
        $this->assertNotSame([], $m, 'The table version constant must be defined in the plugin header.');
        $this->assertTrue((int) ($m[1] ?? 0) > 2,
            "The schema bump above 2 re-runs migrate()/dbDelta on every 0.1.x install, so existing visitors tables gain ip_hash in place.");
    }

    public function testTouchVisitorWritesTheVisitorHashAndBeaconThreadsBothStores(): void
    {
        $store = (string) file_get_contents(SITEGUARD_DIR . 'src/Wp/Store/WpdbPeopleStore.php');
        $this->assertTrue(str_contains($store, 'ua, ip_hash, profile'),
            'The visitor INSERT lists ip_hash right after ua, mirroring the session shape.');
        $this->assertTrue(str_contains($store, "substr((string) (\$meta['ip_hash'] ?? ''), 0, 40)"),
            'The visitor row writes the latest beacon hash unclipped by the 32-hex keyed shape: same overwrite read the session row gets.');

        // The update semantics, not just the INSERT binding: within the
        // touchVisitor window, the duplicate-key list carries the same
        // empty-skip guard ip/ua use, so a fresh beacon hash overwrites and
        // an empty beacon never clobbers the stored keyed form.
        $touch = (string) substr($store, 0, (int) strpos($store, 'profileFor'));
        $this->assertTrue(str_contains($touch, "ip_hash = IF(VALUES(ip_hash) <> '', VALUES(ip_hash), ip_hash)"),
            'touchVisitor repeat visits re-attribute: the ON DUPLICATE list overwrites ip_hash with the latest non-empty beacon hash, like ip/ua.');

        $beacon = (string) file_get_contents(SITEGUARD_DIR . 'src/Wp/Beacon.php');
        $this->assertSame(3, substr_count($beacon, '\'ip_hash\' => $ipHash,'),
            'The beacon threads its one hash derivation into all three stores: the events row, touchSession, and touchVisitor.');
    }
}
