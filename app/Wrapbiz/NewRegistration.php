<?php

namespace App\Wrapbiz;

final readonly class NewRegistration
{
    /**
     * @param  string  $codeHash  raw SHA-256 of the register code
     * @param  string  $sealedCredential  raw sealed-box bytes
     * @param  string  $orgFingerprint  raw 32-byte HMAC of the bank organisation id
     * @param  string  $userFingerprint  raw 32-byte HMAC of the bank user reference
     * @param  non-empty-list<NewAccount>  $accounts  exactly one: register_connection() refuses any other number
     * @param  string  $ipHash  raw HMAC of the client IP
     */
    public function __construct(
        public string $codeHash,
        public string $provider,
        public string $webhookUrl,
        public string $connectionId,
        public string $sealedCredential,
        public string $orgFingerprint,
        public string $userFingerprint,
        public array $accounts,
        public string $ipHash,
    ) {}
}
