<?php

namespace Tests\Unit;

use App\Kbiz\KbizConfigException;
use App\Security\TrustedProxies;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class TrustedProxiesTest extends TestCase
{
    public function test_empty_means_no_proxy_is_trusted(): void
    {
        $this->assertSame([], TrustedProxies::parse(null));
        $this->assertSame([], TrustedProxies::parse(''));
        $this->assertSame([], TrustedProxies::parse('   '));
    }

    public function test_explicit_addresses_and_ranges_are_accepted(): void
    {
        $this->assertSame(
            ['10.0.4.0/24', '10.0.5.7', '2001:db8:10::/48', 'fd00::1', '10.1.0.0/16', '::1', '::1/128', '2001:db8::/32', '2003::/32', 'fd12:3456::/32', '127.0.0.1', '2001:200::/32'],
            TrustedProxies::parse(' 10.0.4.0/24, 10.0.5.7,2001:db8:10::/48 , fd00::1,10.1.0.0/16,10.0.5.7,::1,::1/128,2001:db8::/32,2003::/32,fd12:3456::/32,127.0.0.1,2001:200::/32'),
        );
    }

    /**
     * @return iterable<string, array{mixed}>
     */
    public static function unsafe(): iterable
    {
        foreach (['*', '**', 'REMOTE_ADDR', '0.0.0.0/0', '::/0', '0.0.0.0/1,128.0.0.0/1', '10.0.0.0/7', '2001::/31',
            '10.0.0.1/33', '::1/129', '10.0.0.1/', '10.0.0.1/ 8', '10.0.0.1/08x', 'proxy.internal', '10.0.0', '1.2.3.4,', ',1.2.3.4', '10.0.0.1/-1'] as $value) {
            yield $value => [$value];
        }
        yield 'not a string' => [['10.0.0.1']];

        // SEC-R1-06 / BUG-R2-03: IPv4 broader than /16, and IPv6 ranges that
        // overlap an IPv4-embedding block, would trust ordinary IPv4 clients.
        foreach (['10.0.0.0/8', '10.0.0.0/15', '1.0.0.0/8', '0.0.0.0/8',
            '::/32', '::/96', '::ffff:0:0/96', '::ffff:0.0.0.0/96', '::ffff:10.0.0.0/104', '::ffff:10.0.0.1', '::2', '::10.0.0.1',
            '64:ff9b::/96', '64:ff9b::/64', '64:ff9b::a00:1', '2002::/16', '2002::/32', '2002:c633:6409::1', '::/127'] as $value) {
            yield "embeds or too broad: {$value}" => [$value];
        }

        // SEC-R2-06: the rest of the worker's netguard IPv6 blocklist.
        foreach (['64:ff9b:1::/48', '64:ff9b:1::a00:1', '::ffff:0:0:0/96', '::ffff:0:a00:1', '2001::/32', '2001:0:4136:e378::1',
            '2001:1ff::/32', 'fe80::/10', 'fe80::5efe:a00:1', 'febf::1', 'fec0::/10', 'fec0::1', 'ff00::/8', 'ff02::1', '100::/64', '100::1'] as $value) {
            yield "netguard range: {$value}" => [$value];
        }
    }

    #[DataProvider('unsafe')]
    public function test_wildcards_catch_alls_and_garbage_are_rejected_naming_the_variable(mixed $value): void
    {
        $this->expectException(KbizConfigException::class);
        $this->expectExceptionMessageMatches('/^TRUSTED_PROXIES /');

        TrustedProxies::parse($value);
    }
}
