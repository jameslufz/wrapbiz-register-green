<?php

/*
 * Raw WRAPBIZ_* values, parsed and validated by App\Wrapbiz\WrapbizSettings.
 */

return [
    'seal_public_key' => env('WRAPBIZ_SEAL_PUBLIC_KEY'),
    'fingerprint_key' => env('WRAPBIZ_FINGERPRINT_KEY'),
    'ip_hash_key' => env('WRAPBIZ_IP_HASH_KEY'),
    'signing_public_keys' => env('WRAPBIZ_SIGNING_PUBLIC_KEYS'),
    'trusted_proxies' => env('TRUSTED_PROXIES'),
    'bank_logins_per_minute' => env('WRAPBIZ_BANK_LOGINS_PER_MINUTE'),
    'bank_logins_per_hour' => env('WRAPBIZ_BANK_LOGINS_PER_HOUR'),
];
