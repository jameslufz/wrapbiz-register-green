<?php

namespace App\Security;

use App\Kbiz\KbizConfigException;

/**
 * TRUSTED_PROXIES: a comma-separated list of explicit proxy IPs or CIDRs.
 * Wildcards ("*", "**", "REMOTE_ADDR") and catch-all ranges would let any
 * client spoof X-Forwarded-For and dodge every per-IP limit, so they are
 * rejected rather than silently accepted.
 */
final class TrustedProxies
{
    private const string VARIABLE = 'TRUSTED_PROXIES';

    private const int MIN_IPV4_PREFIX = 16;

    private const int MIN_IPV6_PREFIX = 32;

    /**
     * The worker's netguard IPv6 blocklist minus unique-local fc00::/7 and
     * the documentation ranges, which are ordinary places for a proxy.
     * Trusting any part of these can end up trusting ordinary clients: they
     * embed IPv4 addresses (mapped, compatible, SIIT, NAT64, Teredo, 6to4,
     * ISATAP link-local) or are not unicast at all.
     */
    private const array REFUSED_IPV6_RANGES = [
        ['::', 96],
        ['::ffff:0:0', 96],
        ['::ffff:0:0:0', 96],
        ['64:ff9b::', 96],
        ['64:ff9b:1::', 48],
        ['100::', 64],
        ['2001::', 23],
        ['2002::', 16],
        ['fe80::', 10],
        ['fec0::', 10],
        ['ff00::', 8],
    ];

    /** The IPv6 loopback lies inside ::/96 but cannot carry another client. */
    private const string IPV6_LOOPBACK = '::1';

    /**
     * @return list<string>
     */
    public static function parse(mixed $value): array
    {
        if ($value === null || (is_string($value) && trim($value) === '')) {
            return [];
        }
        if (! is_string($value)) {
            throw new KbizConfigException(self::VARIABLE.' must be a comma-separated list of IP addresses or CIDR ranges.');
        }

        $proxies = [];
        foreach (explode(',', $value) as $entry) {
            $entry = trim($entry);
            if (! self::isAcceptable($entry)) {
                throw new KbizConfigException(self::VARIABLE.' entries must be explicit IP addresses or CIDR ranges (no wildcards; at least /'
                    .self::MIN_IPV4_PREFIX.' for IPv4, /'.self::MIN_IPV6_PREFIX.' for IPv6; no IPv6 range that embeds IPv4 addresses or is not unicast:'
                    .' ::/96 except ::1, ::ffff:0:0/96, ::ffff:0:0:0/96, 64:ff9b::/96, 64:ff9b:1::/48, 100::/64, 2001::/23,'
                    .' 2002::/16, fe80::/10, fec0::/10, ff00::/8).');
            }
            $proxies[] = $entry;
        }

        return array_values(array_unique($proxies));
    }

    private static function isAcceptable(string $entry): bool
    {
        $parts = explode('/', $entry, 2);
        $packed = @inet_pton($parts[0]);
        if ($packed === false || filter_var($parts[0], FILTER_VALIDATE_IP) === false) {
            return false;
        }

        $maxPrefix = strlen($packed) * 8;
        if (count($parts) === 1) {
            $prefix = $maxPrefix;
        } elseif (preg_match('/^[0-9]{1,3}$/D', $parts[1]) === 1) {
            $prefix = (int) $parts[1];
        } else {
            return false;
        }

        if ($maxPrefix === 32) {
            return $prefix >= self::MIN_IPV4_PREFIX && $prefix <= 32;
        }
        if ($prefix < self::MIN_IPV6_PREFIX || $prefix > 128) {
            return false;
        }
        if ($prefix === 128 && $packed === inet_pton(self::IPV6_LOOPBACK)) {
            return true;
        }

        foreach (self::REFUSED_IPV6_RANGES as [$network, $networkPrefix]) {
            if (self::sharePrefix($packed, (string) inet_pton($network), min($prefix, $networkPrefix))) {
                return false;
            }
        }

        return true;
    }

    /**
     * Two CIDR blocks overlap exactly when they agree on the shorter of
     * their two prefixes.
     */
    private static function sharePrefix(string $a, string $b, int $bits): bool
    {
        $fullBytes = intdiv($bits, 8);
        if (substr($a, 0, $fullBytes) !== substr($b, 0, $fullBytes)) {
            return false;
        }

        $remainingBits = $bits % 8;
        if ($remainingBits === 0) {
            return true;
        }
        $mask = (0xFF << (8 - $remainingBits)) & 0xFF;

        return (ord($a[$fullBytes]) & $mask) === (ord($b[$fullBytes]) & $mask);
    }
}
