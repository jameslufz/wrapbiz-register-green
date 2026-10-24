<?php

namespace App\Http\Controllers;

use App\Wrapbiz\SigningPublicKey;
use App\Wrapbiz\WrapbizSettings;
use Illuminate\Http\JsonResponse;

/**
 * Public Ed25519 keys customers use to verify webhook signatures
 * (Standard Webhooks, "v1a" scheme). Served as a JWK set with the raw
 * base64 key alongside for libraries that take it directly.
 */
final class WellKnownKeysController extends Controller
{
    public function __invoke(WrapbizSettings $settings): JsonResponse
    {
        return response()->json([
            'scheme' => 'standard-webhooks-v1a-ed25519',
            'signed_content' => '{webhook-id}.{webhook-timestamp}.{raw body}',
            'keys' => array_map(fn (SigningPublicKey $key) => [
                'kid' => $key->kid,
                'kty' => 'OKP',
                'crv' => 'Ed25519',
                'alg' => 'EdDSA',
                'use' => 'sig',
                'x' => $key->base64Url(),
                'public_key_base64' => $key->base64(),
            ], $settings->signingKeys),
        ], 200, ['Cache-Control' => 'public, max-age=300'], JSON_UNESCAPED_SLASHES);
    }
}
