<?php

namespace Tests\Unit;

use App\Kbiz\KbizConfigException;
use App\Wrapbiz\WrapbizSettings;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class WrapbizSettingsTest extends TestCase
{
    /**
     * @return array<string, string>
     */
    private static function valid(): array
    {
        return [
            'seal_public_key' => base64_encode(str_repeat('s', 32)),
            'fingerprint_key' => base64_encode(str_repeat('f', 32)),
            'ip_hash_key' => base64_encode(str_repeat('i', 48)),
            'signing_public_keys' => 'a:'.base64_encode(str_repeat('a', 32)).', b:'.base64_encode(str_repeat('b', 32)),
        ];
    }

    public function test_parses_valid_settings(): void
    {
        $settings = WrapbizSettings::fromArray(self::valid());

        $this->assertSame(str_repeat('s', 32), $settings->sealPublicKey);
        $this->assertCount(2, $settings->signingKeys);
        $this->assertSame('b', $settings->signingKeys[1]->kid);
        $this->assertSame(base64_encode(str_repeat('b', 32)), $settings->signingKeys[1]->base64());
        $this->assertSame(rtrim(strtr(base64_encode(str_repeat('b', 32)), '+/', '-_'), '='), $settings->signingKeys[1]->base64Url());
        $this->assertSame([], $settings->trustedProxies);
        $this->assertSame(20, $settings->bankLoginsPerMinute);
        $this->assertSame(200, $settings->bankLoginsPerHour);
    }

    public function test_the_catch_up_window_is_no_longer_a_setting(): void
    {
        $this->assertFalse(property_exists(WrapbizSettings::class, 'catchUpDays'), 'register_connection returns it');
        $this->assertStringNotContainsString('CATCHUP', (string) file_get_contents(dirname(__DIR__, 2).'/config/wrapbiz.php'));
        $this->assertStringNotContainsString('CATCHUP', (string) file_get_contents(dirname(__DIR__, 2).'/.env.example'));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function separateKeys(): iterable
    {
        $a = str_repeat('a', 32);

        yield 'different 32-byte keys' => [$a, str_repeat('b', 32)];
        yield 'differs only in the last byte' => [$a, str_repeat('a', 31).'b'];
        yield 'long key whose hash differs' => [str_repeat('x', 65), str_repeat('y', 65)];
        yield 'long key and an unrelated short key' => [str_repeat('x', 100), $a];
    }

    #[DataProvider('separateKeys')]
    public function test_separate_hmac_keys_are_accepted(string $fingerprintKey, string $ipHashKey): void
    {
        $settings = WrapbizSettings::fromArray([
            ...self::valid(),
            'fingerprint_key' => base64_encode($fingerprintKey),
            'ip_hash_key' => base64_encode($ipHashKey),
        ]);

        $this->assertSame($ipHashKey, $settings->ipHashKey);
    }

    /**
     * Each pair is the same HMAC-SHA256 key, or one key starts with the other.
     *
     * @return iterable<string, array{string, string}>
     */
    public static function overlappingKeys(): iterable
    {
        $key = random_bytes(40);
        $long = random_bytes(65);

        yield 'identical' => [$key, $key];
        yield 'ip key extends the fingerprint key' => [$key, $key.random_bytes(8)];
        yield 'fingerprint key extends the ip key' => [$key.random_bytes(8), $key];
        yield 'zero-padded copy (same HMAC key)' => [$key, $key."\0\0\0"];
        yield 'long key and its SHA-256' => [$long, hash('sha256', $long, true)];
        yield 'SHA-256 of the long ip key' => [hash('sha256', $long, true), $long];
        yield 'long key and its zero-padded SHA-256' => [$long, hash('sha256', $long, true).str_repeat("\0", 8)];
        yield 'identical long keys' => [$long, $long];
    }

    #[DataProvider('overlappingKeys')]
    public function test_the_ip_hash_key_must_be_separate_from_the_fingerprint_key(string $fingerprintKey, string $ipHashKey): void
    {
        $this->expectException(KbizConfigException::class);
        $this->expectExceptionMessage('WRAPBIZ_IP_HASH_KEY must be a separately generated key, not WRAPBIZ_FINGERPRINT_KEY or a key that starts with it.');

        WrapbizSettings::fromArray([
            ...self::valid(),
            'fingerprint_key' => base64_encode($fingerprintKey),
            'ip_hash_key' => base64_encode($ipHashKey),
        ]);
    }

    public function test_parses_proxies_and_login_budget(): void
    {
        $settings = WrapbizSettings::fromArray([
            ...self::valid(),
            'trusted_proxies' => '10.0.4.0/24',
            'bank_logins_per_minute' => '7',
            'bank_logins_per_hour' => 70,
        ]);

        $this->assertSame(['10.0.4.0/24'], $settings->trustedProxies);
        $this->assertSame(7, $settings->bankLoginsPerMinute);
        $this->assertSame(70, $settings->bankLoginsPerHour);
    }

    /**
     * @return iterable<string, array{0: string, 1: mixed, 2: string}>
     */
    public static function invalid(): iterable
    {
        yield 'seal missing' => ['seal_public_key', null, 'WRAPBIZ_SEAL_PUBLIC_KEY is not set.'];
        yield 'seal not base64' => ['seal_public_key', '***', 'WRAPBIZ_SEAL_PUBLIC_KEY must be base64.'];
        yield 'seal wrong size' => ['seal_public_key', base64_encode('short'), 'WRAPBIZ_SEAL_PUBLIC_KEY must decode to a 32-byte'];
        yield 'fingerprint missing' => ['fingerprint_key', '', 'WRAPBIZ_FINGERPRINT_KEY is not set.'];
        yield 'fingerprint short' => ['fingerprint_key', base64_encode(str_repeat('x', 31)), 'WRAPBIZ_FINGERPRINT_KEY must decode to at least 32 bytes.'];
        yield 'ip key short' => ['ip_hash_key', base64_encode('x'), 'WRAPBIZ_IP_HASH_KEY must decode to at least 32 bytes.'];
        yield 'signing missing' => ['signing_public_keys', null, 'WRAPBIZ_SIGNING_PUBLIC_KEYS is not set.'];
        yield 'signing no kid' => ['signing_public_keys', base64_encode(str_repeat('a', 32)), 'WRAPBIZ_SIGNING_PUBLIC_KEYS must be a comma-separated list'];
        yield 'signing duplicate kid' => ['signing_public_keys', 'a:'.base64_encode(str_repeat('a', 32)).',a:'.base64_encode(str_repeat('b', 32)), 'unique'];
        yield 'signing wrong size' => ['signing_public_keys', 'a:'.base64_encode('short'), 'entry "a" must be a base64 32-byte Ed25519 public key.'];
        yield 'proxies wildcard' => ['trusted_proxies', '*', 'TRUSTED_PROXIES entries must be explicit'];
        yield 'login budget zero' => ['bank_logins_per_minute', '0', 'WRAPBIZ_BANK_LOGINS_PER_MINUTE must be a positive whole number.'];
        yield 'login budget text' => ['bank_logins_per_hour', 'lots', 'WRAPBIZ_BANK_LOGINS_PER_HOUR must be a positive whole number.'];
    }

    #[DataProvider('invalid')]
    public function test_rejects_invalid_settings_naming_the_variable(string $key, mixed $value, string $message): void
    {
        $this->expectException(KbizConfigException::class);
        $this->expectExceptionMessage($message);

        WrapbizSettings::fromArray([...self::valid(), $key => $value]);
    }
}
