<?php

namespace App\Security;

use App\Kbiz\KbizConfigException;

/**
 * Seals JSON to the worker's X25519 public key (libsodium sealed box).
 * This app holds no private key and can never open what it seals.
 */
final readonly class CredentialSealer
{
    public function __construct(private string $publicKey)
    {
        if (strlen($publicKey) !== SODIUM_CRYPTO_BOX_PUBLICKEYBYTES) {
            throw new KbizConfigException('WRAPBIZ_SEAL_PUBLIC_KEY must decode to a 32-byte X25519 public key.');
        }
    }

    /**
     * @param  array<string, string>  $payload
     */
    public function seal(#[\SensitiveParameter] array $payload): string
    {
        $json = json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        try {
            return sodium_crypto_box_seal($json, $this->publicKey);
        } finally {
            sodium_memzero($json);
        }
    }
}
