<?php

namespace App\Security;

/**
 * The audit log records HMAC-SHA256(WRAPBIZ_IP_HASH_KEY, ip), never the raw IP.
 */
final readonly class IpHasher
{
    public function __construct(#[\SensitiveParameter] private string $key) {}

    public function hash(string $ip): string
    {
        return hash_hmac('sha256', $ip, $this->key, true);
    }
}
