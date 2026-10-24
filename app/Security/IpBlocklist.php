<?php

namespace App\Security;

/**
 * Decides whether an IP address is publicly routable. Mirrors the worker's
 * dial-time SSRF guard so a URL accepted here is not rejected at delivery.
 */
final class IpBlocklist
{
    private const array BLOCKED_V4 = [
        '0.0.0.0/8',          // "this network", unspecified
        '10.0.0.0/8',         // private
        '100.64.0.0/10',      // CGNAT
        '127.0.0.0/8',        // loopback
        '169.254.0.0/16',     // link-local, includes 169.254.169.254 metadata
        '172.16.0.0/12',      // private
        '192.0.0.0/24',       // IETF protocol assignments
        '192.0.2.0/24',       // documentation
        '192.88.99.0/24',     // 6to4 relay anycast
        '192.168.0.0/16',     // private
        '198.18.0.0/15',      // benchmarking
        '198.51.100.0/24',    // documentation
        '203.0.113.0/24',     // documentation
        '224.0.0.0/4',        // multicast
        '240.0.0.0/4',        // reserved, includes 255.255.255.255 broadcast
    ];

    /**
     * Only global unicast (2000::/3) is accepted at all, which already
     * excludes ::, ::1, IPv4-mapped/compatible, NAT64 64:ff9b::/96, ULA,
     * link-local and multicast. These are the special ranges inside 2000::/3.
     */
    private const array BLOCKED_V6 = [
        '2001::/23',          // IETF protocol assignments, includes Teredo 2001::/32
        '2001:db8::/32',      // documentation
        '2002::/16',          // 6to4
        '3fff::/20',          // documentation
    ];

    private const string GLOBAL_UNICAST_V6 = '2000::/3';

    public static function isPublic(string $ip): bool
    {
        $packed = @inet_pton($ip);
        if ($packed === false) {
            return false;
        }

        if (strlen($packed) === 4) {
            return ! self::matchesAny($packed, self::BLOCKED_V4);
        }

        return self::inCidr($packed, self::GLOBAL_UNICAST_V6)
            && ! self::matchesAny($packed, self::BLOCKED_V6);
    }

    /**
     * @param  list<string>  $cidrs
     */
    private static function matchesAny(string $packed, array $cidrs): bool
    {
        foreach ($cidrs as $cidr) {
            if (self::inCidr($packed, $cidr)) {
                return true;
            }
        }

        return false;
    }

    private static function inCidr(string $packed, string $cidr): bool
    {
        [$network, $prefixLength] = explode('/', $cidr);
        $networkPacked = inet_pton($network);
        if ($networkPacked === false || strlen($networkPacked) !== strlen($packed)) {
            return false;
        }

        $prefixLength = (int) $prefixLength;
        $fullBytes = intdiv($prefixLength, 8);
        if (strncmp($packed, $networkPacked, $fullBytes) !== 0) {
            return false;
        }

        $remainingBits = $prefixLength % 8;
        if ($remainingBits === 0) {
            return true;
        }

        $mask = (0xFF << (8 - $remainingBits)) & 0xFF;

        return (ord($packed[$fullBytes]) & $mask) === (ord($networkPacked[$fullBytes]) & $mask);
    }
}
