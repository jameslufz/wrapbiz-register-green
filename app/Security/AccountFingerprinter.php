<?php

namespace App\Security;

/**
 * Stable dedup keys that do not reveal the underlying identifiers:
 *   account_fingerprint = HMAC-SHA256(WRAPBIZ_FINGERPRINT_KEY, "<provider>:<digits>")
 *   org_fingerprint     = HMAC-SHA256(WRAPBIZ_FINGERPRINT_KEY, "<provider>:org:<org id>")
 *   user_fingerprint    = HMAC-SHA256(WRAPBIZ_FINGERPRINT_KEY, "<provider>:user:<user ref>")
 * The worker recomputes all three with the same key before it polls.
 */
final readonly class AccountFingerprinter
{
    public function __construct(#[\SensitiveParameter] private string $key) {}

    public function fingerprint(string $provider, AccountNumber $number): string
    {
        return hash_hmac('sha256', $provider.':'.$number->digits, $this->key, true);
    }

    public function organisation(string $provider, string $orgId): string
    {
        return hash_hmac('sha256', $provider.':org:'.$orgId, $this->key, true);
    }

    public function user(string $provider, string $userRef): string
    {
        return hash_hmac('sha256', $provider.':user:'.$userRef, $this->key, true);
    }
}
