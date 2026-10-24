<?php

namespace App\Kbiz;

final readonly class QrChallenge
{
    /**
     * @param  string  $imageDataUri  always a data:image/...;base64 URI, safe to put in an <img src>
     */
    public function __construct(
        public string $imageDataUri,
        public int $expiresAt,
    ) {}
}
