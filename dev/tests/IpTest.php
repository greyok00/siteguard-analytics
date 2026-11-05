<?php
declare(strict_types=1);

namespace SiteGuard\Tests;

use SiteGuard\Core\Ip;

/**
 * Tests for address normalisation, IPv6 prefix collapse, CIDR matching, and
 * trusted-proxy header resolution.
 */
final class IpTest extends TestCase
{
    public function testNormalizesIpv4AndIpv6(): void
    {
        $this->assertSame('203.0.113.10', Ip::normalize(' 203.0.113.10 '));
        $this->assertSame('::1', Ip::normalize('[::1]:443'));
        $this->assertSame('2001:db8::1', Ip::normalize('2001:0db8:0:0:0:0:0:1'));
        $this->assertSame('198.51.100.4', Ip::normalize('198.51.100.4:8080'));
        $this->assertNull(Ip::normalize('not-an-ip'));
        $this->assertNull(Ip::normalize(''));
    }

    public function testSubjectCollapsesIpv6ToSlash64(): void
    {
        $this->assertSame('ip4:cb00710a', Ip::subject('203.0.113.10'));

        $a = Ip::subject('2001:db8:1:2:aaaa::1');
        $b = Ip::subject('2001:db8:1:2:bbbb::2');
        $this->assertSame($a, $b, 'Two addresses in one /64 must share a counter subject.');

        $c = Ip::subject('2001:db8:1:3::1');
        $this->assertNotSame($a, $c, 'A different /64 must be a different subject.');
    }

    public function testInCidr(): void
    {
        $this->assertTrue(Ip::inCidr('10.1.2.3', '10.0.0.0/8'));
        $this->assertFalse(Ip::inCidr('11.1.2.3', '10.0.0.0/8'));
        $this->assertTrue(Ip::inCidr('192.168.1.130', '192.168.1.128/25'));
        $this->assertFalse(Ip::inCidr('192.168.1.127', '192.168.1.128/25'));
        $this->assertTrue(Ip::inCidr('2001:db8::1', '2001:db8::/32'));
        $this->assertFalse(Ip::inCidr('203.0.113.1', '::/0'), 'Address families must not be compared.');
    }

    public function testForwardedHeadersIgnoredFromUntrustedPeer(): void
    {
        $headers = ['X-Forwarded-For' => '1.2.3.4'];
        $this->assertSame(
            '203.0.113.9',
            Ip::client('203.0.113.9', $headers, ''),
            'A client must not choose its own address by sending a header.'
        );
    }

    public function testForwardedChainResolvedFromTrustedProxy(): void
    {
        $headers = ['X-Forwarded-For' => '198.51.100.7, 10.0.0.5'];
        $this->assertSame(
            '198.51.100.7',
            Ip::client('10.0.0.2', $headers, '10.0.0.0/8'),
            'The first untrusted hop from the right is the client.'
        );
    }

    public function testForwardedChainSpoofInsideTrustedRangeIsIgnored(): void
    {
        // All hops are trusted proxies; the leftmost entry is still the client.
        $headers = ['X-Forwarded-For' => '198.51.100.7, 10.0.0.5, 10.0.0.2'];
        $this->assertSame('198.51.100.7', Ip::client('10.0.0.1', $headers, '10.0.0.0/8'));
    }

    public function testForwardedChainIsCapped(): void
    {
        $chain = implode(', ', array_fill(0, 50, '198.51.100.1')) . ', 203.0.113.77';
        $this->assertSame(
            '198.51.100.1',
            Ip::client('10.0.0.2', ['X-Forwarded-For' => $chain], '10.0.0.0/8'),
            'Only the first ten entries are read.'
        );
    }

    public function testRfcForwardedHeader(): void
    {
        $headers = ['Forwarded' => 'for="[2001:db8::5]";proto=https'];
        $this->assertSame('2001:db8::5', Ip::client('10.0.0.2', $headers, '10.0.0.0/8'));
    }
}
