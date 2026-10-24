<?php

namespace App\Wrapbiz;

final readonly class NewAccount
{
    /**
     * @param  string  $fingerprint  raw 32-byte HMAC
     * @param  string  $sealed  raw sealed-box bytes
     */
    public function __construct(
        public string $id,
        public string $fingerprint,
        public string $masked,
        public string $sealed,
    ) {}
}
