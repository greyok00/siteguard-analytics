<?php
declare(strict_types=1);

namespace SiteGuard\Tests;

use SiteGuard\Core\Crypto;

/**
 * Tests for identifiers, keyed and versioned fingerprints, and subject
 * hashing.
 */
final class CryptoTest extends TestCase
{
    public function testIdsAre128BitHex(): void
    {
        $id = Crypto::randomId();
        $this->assertSame(32, strlen($id));
        $this->assertTrue(Crypto::isId($id));
        $this->assertFalse(Crypto::isId(strtoupper($id)));
        $this->assertFalse(Crypto::isId(''));
        $this->assertFalse(Crypto::isId(str_repeat('z', 32)));
        $this->assertNotSame($id, Crypto::randomId());
    }

    public function testFingerprintIgnoresSignalOrder(): void
    {
        $crypto = new Crypto('site-secret', 'fp-secret', 1);
        $a = $crypto->fingerprint(['lang' => 'en-US', 'tz' => 'America/Phoenix', 'screen' => '1900x1000']);
        $b = $crypto->fingerprint(['screen' => '1900x1000', 'tz' => 'America/Phoenix', 'lang' => 'en-US']);
        $this->assertSame($a, $b);
    }

    public function testFingerprintIsVersionedAndKeyed(): void
    {
        $v1 = new Crypto('site-secret', 'fp-secret', 1);
        $v2 = new Crypto('site-secret', 'fp-secret', 2);
        $other = new Crypto('site-secret', 'different-salt', 1);
        $signals = ['lang' => 'en-US', 'tz' => 'UTC'];

        $this->assertTrue(str_starts_with($v1->fingerprint($signals), 'fp1:'));
        $this->assertTrue(str_starts_with($v2->fingerprint($signals), 'fp2:'));
        $this->assertNotSame($v1->fingerprint($signals), $other->fingerprint($signals));
    }

    public function testFingerprintNormalizesCaseAndWhitespace(): void
    {
        $crypto = new Crypto('site-secret', 'fp-secret', 1);
        $this->assertSame(
            $crypto->fingerprint(['lang' => 'EN-us']),
            $crypto->fingerprint(['lang' => '  en-US  '])
        );
    }

    public function testSubjectIsKeyedAndPrefixed(): void
    {
        $crypto = new Crypto('one', 'fp', 1);
        $other = new Crypto('two', 'fp', 1);

        $subject = $crypto->subject('ua', 'Mozilla/5.0');
        $this->assertTrue(str_starts_with($subject, 'ua:'));
        $this->assertSame(35, strlen($subject));
        $this->assertNotSame($subject, $other->subject('ua', 'Mozilla/5.0'));
        $this->assertNotSame($subject, $crypto->subject('ip', 'Mozilla/5.0'));
    }

    public function testSignatureRoundTrip(): void
    {
        $crypto = new Crypto('one', 'fp', 1);
        $sig = $crypto->sign('confirm', 'payload');
        $this->assertTrue($crypto->verify('confirm', 'payload', $sig));
        $this->assertFalse($crypto->verify('confirm', 'payload2', $sig));
        $this->assertFalse($crypto->verify('other', 'payload', $sig));
    }
}
