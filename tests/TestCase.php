<?php

namespace Tests;

use App\Security\DnsResolver;
use Illuminate\Foundation\Testing\TestCase as BaseTestCase;
use Illuminate\Support\Facades\Http;
use Tests\Support\FakeBank;
use Tests\Support\FakeDnsResolver;

abstract class TestCase extends BaseTestCase
{
    protected string $sealSecretKeypair;

    protected string $signingSecretKey;

    protected function setUp(): void
    {
        parent::setUp();

        // No test may ever reach a real host; FakeBank and explicit fakes only.
        Http::preventStrayRequests();

        $this->sealSecretKeypair = sodium_crypto_box_keypair();
        $signing = sodium_crypto_sign_keypair();
        $this->signingSecretKey = sodium_crypto_sign_secretkey($signing);

        config([
            'kbiz' => FakeBank::config(),
            'wrapbiz' => [
                'seal_public_key' => base64_encode(sodium_crypto_box_publickey($this->sealSecretKeypair)),
                'fingerprint_key' => base64_encode(str_repeat('f', 32)),
                'ip_hash_key' => base64_encode(str_repeat('i', 32)),
                'signing_public_keys' => 'k1:'.base64_encode(sodium_crypto_sign_publickey($signing)),
                'trusted_proxies' => null,
                'bank_logins_per_minute' => null,
                'bank_logins_per_hour' => null,
            ],
        ]);

        $this->app->instance(DnsResolver::class, new FakeDnsResolver([
            'hooks.example.com' => ['93.184.216.34', '2606:2800:220:1:248:1893:25c8:1946'],
        ]));
    }
}
