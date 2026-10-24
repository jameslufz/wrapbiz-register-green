<?php

/**
 * Verify a wrapbiz webhook (Standard Webhooks, Ed25519 "v1a").
 *
 * $rawBody    the exact request body bytes (do NOT re-encode parsed JSON)
 * $headers    lower-case header names => values
 * $publicKeys base64 Ed25519 public keys from /.well-known/wrapbiz-keys.json
 *
 * Returns true if any v1a signature verifies with any trusted key and the
 * timestamp is within the tolerance. Deduplicate on the webhook-id header.
 */
function wrapbiz_verify_webhook(string $rawBody, array $headers, array $publicKeys, int $toleranceSeconds = 300): bool
{
    $id = $headers['webhook-id'] ?? '';
    $timestamp = $headers['webhook-timestamp'] ?? '';
    $signatureHeader = $headers['webhook-signature'] ?? '';

    if ($id === '' || $signatureHeader === '' || ! ctype_digit($timestamp)) {
        return false;
    }
    if (abs(time() - (int) $timestamp) > $toleranceSeconds) {
        return false;
    }

    $signedContent = $id.'.'.$timestamp.'.'.$rawBody;

    foreach (explode(' ', $signatureHeader) as $entry) {
        [$version, $signature] = array_pad(explode(',', $entry, 2), 2, '');
        if ($version !== 'v1a') {
            continue;
        }

        $signatureBytes = base64_decode($signature, true);
        if ($signatureBytes === false || strlen($signatureBytes) !== SODIUM_CRYPTO_SIGN_BYTES) {
            continue;
        }

        foreach ($publicKeys as $publicKey) {
            $keyBytes = base64_decode($publicKey, true);
            if ($keyBytes !== false && strlen($keyBytes) === SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES
                && sodium_crypto_sign_verify_detached($signatureBytes, $signedContent, $keyBytes)) {
                return true;
            }
        }
    }

    return false;
}

/**
 * Verifies a delivery and applies it at most once.
 *
 * $applyOnce(string $webhookId, array $event): void must, in ONE database
 * transaction, insert $webhookId into a table with a UNIQUE constraint and
 * apply the event only if that insert added a row. Credit money idempotently
 * on (data.account.id, data.transaction.ref) as well. Marking the id as seen
 * before the effect is committed would lose the event if your process
 * crashes in between, because wrapbiz will not redeliver an event you
 * already answered 2xx for.
 *
 * Returns the HTTP status to reply with: 401 for a bad signature or a
 * timestamp outside the tolerance, 400 for a non-JSON body, otherwise 200
 * (also for a redelivered webhook-id, so delivery stops).
 */
function wrapbiz_handle_webhook(string $rawBody, array $headers, array $publicKeys, callable $applyOnce, int $toleranceSeconds = 300): int
{
    if (! wrapbiz_verify_webhook($rawBody, $headers, $publicKeys, $toleranceSeconds)) {
        return 401;
    }

    $event = json_decode($rawBody, true);
    if (! is_array($event)) {
        return 400;
    }

    $applyOnce($headers['webhook-id'], $event);

    return 200;
}
