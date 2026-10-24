<?php

namespace Tests\Unit;

use App\Security\RateLimitKey;
use PHPUnit\Framework\TestCase;

final class RateLimitKeyTest extends TestCase
{
    public function test_ipv4_addresses_are_keyed_individually(): void
    {
        $this->assertSame('v4:198.51.100.7', RateLimitKey::forIp('198.51.100.7'));
        $this->assertNotSame(RateLimitKey::forIp('198.51.100.7'), RateLimitKey::forIp('198.51.100.8'));
    }

    public function test_ipv6_addresses_in_one_64_share_a_key(): void
    {
        $key = RateLimitKey::forIp('2001:db8:1:2::1');

        $this->assertSame('v6:20010db800010002::/64', $key);
        $this->assertSame($key, RateLimitKey::forIp('2001:db8:1:2:ffff:ffff:ffff:ffff'));
        $this->assertSame($key, RateLimitKey::forIp('2001:0DB8:0001:0002:0:0:0:abcd'));
        $this->assertNotSame($key, RateLimitKey::forIp('2001:db8:1:3::1'));
    }

    public function test_ipv4_mapped_ipv6_is_treated_as_the_ipv4_address(): void
    {
        $this->assertSame('v4:198.51.100.7', RateLimitKey::forIp('::ffff:198.51.100.7'));
    }

    public function test_unparseable_input_shares_one_key(): void
    {
        $this->assertSame('unknown', RateLimitKey::forIp(null));
        $this->assertSame('unknown', RateLimitKey::forIp(''));
        $this->assertSame('unknown', RateLimitKey::forIp('not-an-ip'));
    }
}
