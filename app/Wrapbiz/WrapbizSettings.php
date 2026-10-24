<?php

namespace App\Wrapbiz;

use App\Kbiz\KbizConfigException;
use App\Security\TrustedProxies;

/**
 * Parses and validates the WRAPBIZ_* key material. Messages name the
 * variable, never its value.
 */
final readonly class WrapbizSettings
{
    private const int MIN_HMAC_KEY_BYTES = 32;

    private const int DEFAULT_BANK_LOGINS_PER_MINUTE = 20;

    private const int DEFAULT_BANK_LOGINS_PER_HOUR = 200;

    /** HMAC-SHA256 hashes longer keys first, so such a key is the same key as its SHA-256. */
    private const int HMAC_BLOCK_BYTES = 64;

    /**
     * @param  non-empty-list<SigningPublicKey>  $signingKeys
     * @param  list<string>  $trustedProxies
     */
    private function __construct(
        public string $sealPublicKey,
        #[\SensitiveParameter] public string $fingerprintKey,
        #[\SensitiveParameter] public string $ipHashKey,
        public array $signingKeys,
        public array $trustedProxies,
        public int $bankLoginsPerMinute,
        public int $bankLoginsPerHour,
    ) {}

    /**
     * @param  array<string, mixed>  $raw
     */
    public static function fromArray(#[\SensitiveParameter] array $raw): self
    {
        $sealPublicKey = self::decodeKey('WRAPBIZ_SEAL_PUBLIC_KEY', $raw['seal_public_key'] ?? null);
        if (strlen($sealPublicKey) !== SODIUM_CRYPTO_BOX_PUBLICKEYBYTES) {
            throw new KbizConfigException('WRAPBIZ_SEAL_PUBLIC_KEY must decode to a 32-byte X25519 public key.');
        }

        $fingerprintKey = self::decodeKey('WRAPBIZ_FINGERPRINT_KEY', $raw['fingerprint_key'] ?? null);
        if (strlen($fingerprintKey) < self::MIN_HMAC_KEY_BYTES) {
            throw new KbizConfigException('WRAPBIZ_FINGERPRINT_KEY must decode to at least 32 bytes.');
        }

        $ipHashKey = self::decodeKey('WRAPBIZ_IP_HASH_KEY', $raw['ip_hash_key'] ?? null);
        if (strlen($ipHashKey) < self::MIN_HMAC_KEY_BYTES) {
            throw new KbizConfigException('WRAPBIZ_IP_HASH_KEY must decode to at least 32 bytes.');
        }
        if (self::keysOverlap($fingerprintKey, $ipHashKey)) {
            throw new KbizConfigException('WRAPBIZ_IP_HASH_KEY must be a separately generated key, not WRAPBIZ_FINGERPRINT_KEY or a key that starts with it.');
        }

        return new self(
            $sealPublicKey,
            $fingerprintKey,
            $ipHashKey,
            self::parseSigningKeys($raw['signing_public_keys'] ?? null),
            TrustedProxies::parse($raw['trusted_proxies'] ?? null),
            self::positiveInt('WRAPBIZ_BANK_LOGINS_PER_MINUTE', $raw['bank_logins_per_minute'] ?? null, self::DEFAULT_BANK_LOGINS_PER_MINUTE),
            self::positiveInt('WRAPBIZ_BANK_LOGINS_PER_HOUR', $raw['bank_logins_per_hour'] ?? null, self::DEFAULT_BANK_LOGINS_PER_HOUR),
        );
    }

    /**
     * Mirrors the worker's key separation check: HMAC zero-pads short keys,
     * so a key and any key it is a prefix of are equivalent, and a key longer
     * than the block size is equivalent to its SHA-256.
     */
    private static function keysOverlap(#[\SensitiveParameter] string $a, #[\SensitiveParameter] string $b): bool
    {
        foreach (self::hmacForms($a) as $x) {
            foreach (self::hmacForms($b) as $y) {
                $length = min(strlen($x), strlen($y));
                if ($length > 0 && hash_equals(substr($x, 0, $length), substr($y, 0, $length))) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * @return list<string>
     */
    private static function hmacForms(#[\SensitiveParameter] string $key): array
    {
        return strlen($key) > self::HMAC_BLOCK_BYTES ? [$key, hash('sha256', $key, true)] : [$key];
    }

    private static function positiveInt(string $variable, mixed $value, int $default): int
    {
        if ($value === null || $value === '') {
            return $default;
        }
        if (is_int($value)) {
            $value = (string) $value;
        }
        if (! is_string($value) || preg_match('/^[1-9][0-9]{0,6}$/D', trim($value)) !== 1) {
            throw new KbizConfigException("{$variable} must be a positive whole number.");
        }

        return (int) trim($value);
    }

    /**
     * Format: "<kid>:<base64 32-byte Ed25519 public key>,<kid>:<...>"
     *
     * @return non-empty-list<SigningPublicKey>
     */
    private static function parseSigningKeys(mixed $value): array
    {
        $variable = 'WRAPBIZ_SIGNING_PUBLIC_KEYS';
        if (! is_string($value) || trim($value) === '') {
            throw new KbizConfigException("{$variable} is not set.");
        }

        $keys = [];
        foreach (explode(',', $value) as $entry) {
            $pair = explode(':', trim($entry), 2);
            if (count($pair) !== 2 || preg_match('/^[A-Za-z0-9._-]{1,64}$/D', $pair[0]) !== 1 || isset($keys[$pair[0]])) {
                throw new KbizConfigException("{$variable} must be a comma-separated list of unique <kid>:<base64 key> pairs.");
            }

            $publicKey = base64_decode($pair[1], true);
            if ($publicKey === false || strlen($publicKey) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
                throw new KbizConfigException("{$variable} entry \"{$pair[0]}\" must be a base64 32-byte Ed25519 public key.");
            }

            $keys[$pair[0]] = new SigningPublicKey($pair[0], $publicKey);
        }

        return array_values($keys);
    }

    private static function decodeKey(string $variable, mixed $value): string
    {
        if (! is_string($value) || trim($value) === '') {
            throw new KbizConfigException("{$variable} is not set.");
        }

        $decoded = base64_decode(trim($value), true);
        if ($decoded === false) {
            throw new KbizConfigException("{$variable} must be base64.");
        }

        return $decoded;
    }
}
