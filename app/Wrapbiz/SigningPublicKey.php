<?php

namespace App\Wrapbiz;

final readonly class SigningPublicKey
{
    public function __construct(
        public string $kid,
        public string $publicKey,
    ) {}

    public function base64(): string
    {
        return base64_encode($this->publicKey);
    }

    public function base64Url(): string
    {
        return rtrim(strtr($this->base64(), '+/', '-_'), '=');
    }
}
