<?php

namespace Tests\Unit;

use App\Kbiz\KbizConfigException;
use App\Security\AccountFingerprinter;
use App\Security\AccountNumber;
use App\Security\CredentialSealer;
use App\Security\IpHasher;
use PHPUnit\Framework\TestCase;

final class CredentialSealingTest extends TestCase
{
    public function test_sealed_payload_opens_with_the_worker_keypair(): void
    {
        $keypair = sodium_crypto_box_keypair();
        $sealer = new CredentialSealer(sodium_crypto_box_publickey($keypair));
        $payload = ['connection_id' => '0190-abc', 'session_token' => 'tok/ไทย', 'user_ref' => 'U'];

        $sealed = $sealer->seal($payload);

        $this->assertStringNotContainsString('tok', $sealed);
        $opened = sodium_crypto_box_seal_open($sealed, $keypair);
        $this->assertIsString($opened);
        $this->assertSame($payload, json_decode($opened, true));
        $this->assertSame('{"connection_id":"0190-abc","session_token":"tok/ไทย","user_ref":"U"}', $opened);
    }

    public function test_each_seal_is_unique_and_other_keys_cannot_open_it(): void
    {
        $keypair = sodium_crypto_box_keypair();
        $sealer = new CredentialSealer(sodium_crypto_box_publickey($keypair));

        $first = $sealer->seal(['a' => 'b']);
        $this->assertNotSame($first, $sealer->seal(['a' => 'b']));
        $this->assertFalse(sodium_crypto_box_seal_open($first, sodium_crypto_box_keypair()));
    }

    public function test_rejects_a_public_key_of_the_wrong_size(): void
    {
        $this->expectException(KbizConfigException::class);
        new CredentialSealer('short');
    }

    public function test_fingerprint_is_hmac_of_provider_and_digits(): void
    {
        $key = random_bytes(32);
        $fingerprinter = new AccountFingerprinter($key);

        $formatted = $fingerprinter->fingerprint('kbank', AccountNumber::tryFrom('123-4-56789-0'));
        $plain = $fingerprinter->fingerprint('kbank', AccountNumber::tryFrom('1234567890'));

        $this->assertSame(hash_hmac('sha256', 'kbank:1234567890', $key, true), $plain);
        $this->assertSame($plain, $formatted);
        $this->assertSame(32, strlen($plain));
        $this->assertNotSame($plain, (new AccountFingerprinter(random_bytes(32)))->fingerprint('kbank', AccountNumber::tryFrom('1234567890')));
    }

    public function test_ip_hash_is_keyed(): void
    {
        $key = random_bytes(32);

        $this->assertSame(hash_hmac('sha256', '203.0.113.9', $key, true), (new IpHasher($key))->hash('203.0.113.9'));
    }
}
