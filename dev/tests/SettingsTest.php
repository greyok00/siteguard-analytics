<?php
declare(strict_types=1);

namespace SiteGuard\Tests;

use SiteGuard\Core\Settings;

/**
 * Tests for settings parsing: default merge, enum rejection, limit triples,
 * and removal of settings blocks that no longer exist.
 */
final class SettingsTest extends TestCase
{
    public function testDefaultsAreMergedUnderPartialSettings(): void
    {
        $settings = Settings::from(['profile' => 'strict']);
        $this->assertSame('strict', $settings['profile']);
        $this->assertSame(true, $settings['enabled']);
        $this->assertCount(10, $settings['limits']);
        $this->assertSame(30, $settings['retention']['events']);
        $this->assertSame('full', $settings['ip_storage'], 'The address is stored by default.');
        $this->assertFalse(array_key_exists('ai', $settings), 'The assistant block was removed in 0.1.6.');
    }

    public function testSanitizeRejectsUnknownEnums(): void
    {
        [$clean, $errors] = Settings::sanitize([
            'profile' => 'chaos',
            'consent_mode' => 'whenever',
            'ip_storage' => 'everything',
        ], Settings::from([]));
        $this->assertCount(3, $errors);
        $this->assertSame('balanced', $clean['profile']);
        $this->assertSame('none', $clean['consent_mode']);
        $this->assertSame('full', $clean['ip_storage']);
    }

    public function testSanitizeAcceptsValidValues(): void
    {
        [$clean, $errors] = Settings::sanitize([
            'profile' => 'observe',
            'consent_mode' => 'required',
            'ip_storage' => 'none',
            'collect' => '1',
            'waf_profile' => 'strict',
            'waf_device_hints' => '1',
            'distinct_limit' => '300',
            'strict_factor' => '0.4',
            'account_multiplier' => '3',
            'block_ladder' => '120, 600, 3600',
            'trusted_proxies' => ' 10.0.0.0/8 ',
        ], Settings::from([]));
        $this->assertCount(0, $errors);
        $this->assertSame('observe', $clean['profile']);
        $this->assertSame('strict', $clean['waf_profile']);
        $this->assertSame(true, $clean['waf_device_hints']);
        $this->assertSame(true, $clean['collect']);
        $this->assertSame(300, $clean['distinct_limit']);
        $this->assertSame(0.4, $clean['strict_factor']);
        $this->assertSame(3.0, $clean['account_multiplier']);
        $this->assertSame([120, 600, 3600], $clean['block_ladder']);
        $this->assertSame('10.0.0.0/8', $clean['trusted_proxies']);
    }

    public function testLimitTriplesAreValidated(): void
    {
        [$clean, $errors] = Settings::sanitize([
            'limits' => [
                'html' => ['15', '45', '400'],
                'bogus' => ['1', '2', '3'],
                'search' => ['0', '30', '200'],
            ],
        ], Settings::from([]));
        $this->assertCount(1, $errors);
        $this->assertSame([[10, 15], [60, 45], [3600, 400]], $clean['limits']['html']);
        $this->assertFalse(isset($clean['limits']['bogus']), 'Unknown classes are dropped.');

        $this->assertSame(
            [[10, 10], [60, 30], [3600, 200]],
            $clean['limits']['search'],
            'An invalid triple leaves the previous value in place.'
        );
    }

    public function testAssistantBlockIsNotAcceptedOrStored(): void
    {
        [$clean, $errors] = Settings::sanitize([
            'ai' => ['enabled' => true, 'api_key' => 'sk-test'],
        ], Settings::from([]));
        $this->assertCount(0, $errors);
        $this->assertFalse(array_key_exists('ai', $clean), 'The removed assistant block is not written back.');
    }

    /**
     * Source-level guard: an unchecked checkbox is absent from $_POST, so each
     * of the three boolean controls needs a hidden zero companion or it can be
     * switched on but never off. The view cannot be rendered without WordPress.
     */
    public function testBooleanCheckboxesEmitAHiddenZeroCompanion(): void
    {
        $file = (string) file_get_contents(SITEGUARD_DIR . 'src/Wp/Admin/SettingsPage.php');
        foreach (['enabled', 'collect', 'waf_device_hints'] as $field) {
            $this->assertTrue(
                str_contains($file, '<input type="hidden" name="' . $field . '" value="0">'),
                'A hidden zero must accompany the ' . $field . ' checkbox.'
            );
        }
    }

    public function testWafDefaultsAreBalancedAndArmed(): void
    {
        $settings = Settings::from([]);
        $this->assertSame('balanced', $settings['waf_profile'], 'a fresh install is defended by default.');
        $this->assertSame(true, $settings['waf_device_hints'], 'device-hint enforcement ships armed.');

        // an existing stored choice survives the merge: no silent flips
        $kept = Settings::from(['waf_profile' => 'observe', 'waf_device_hints' => false]);
        $this->assertSame('observe', $kept['waf_profile']);
        $this->assertSame(false, $kept['waf_device_hints']);
    }

    public function testRetentionBoundsAreEnforced(): void
    {
        [$clean, $errors] = Settings::sanitize(['retention' => ['events' => 0, 'audit' => 99999]], Settings::from([]));
        $this->assertCount(2, $errors);
        $this->assertSame(30, $clean['retention']['events']);
        $this->assertSame(365, $clean['retention']['audit']);
    }
}
