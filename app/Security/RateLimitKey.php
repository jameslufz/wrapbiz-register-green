<?php

namespace App\Security;

/**
 * Groups client addresses the way an attacker can cheaply rotate them: one
 * IPv4 address, or one IPv6 /64 (the smallest block a single customer line
 * usually gets).
 */
final class RateLimitKey
{
    private const int IPV6_PREFIX_BYTES = 8;

    public static function forIp(?string $ip): string
    {
        $packed = $ip === null ? false : @inet_pton($ip);
        if ($packed === false) {
            return 'unknown';
        }

        if (strlen($packed) === 4) {
            return 'v4:'.inet_ntop($packed);
        }

        if (str_starts_with($packed, str_repeat("\0", 10)."\xff\xff")) {
            return 'v4:'.inet_ntop(substr($packed, 12));
        }

        return 'v6:'.bin2hex(substr($packed, 0, self::IPV6_PREFIX_BYTES)).'::/64';
    }
}
