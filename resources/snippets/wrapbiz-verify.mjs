// Verify a wrapbiz webhook (Standard Webhooks, Ed25519 "v1a"). Node.js 18+.
//
// rawBody     the exact request body as a Buffer or string (do NOT re-encode parsed JSON)
// headers     lower-case header names => values (e.g. req.headers in Node/Express)
// publicKeys  base64 Ed25519 public keys from /.well-known/wrapbiz-keys.json
//
// Returns true if any v1a signature verifies with any trusted key and the
// timestamp is within the tolerance. Deduplicate on the webhook-id header.
import { createPublicKey, verify } from 'node:crypto'

export function verifyWrapbizWebhook(rawBody, headers, publicKeys, toleranceSeconds = 300) {
  const id = headers['webhook-id'] ?? ''
  const timestamp = headers['webhook-timestamp'] ?? ''
  const signatureHeader = headers['webhook-signature'] ?? ''

  if (id === '' || signatureHeader === '' || !/^\d+$/.test(timestamp)) return false
  if (Math.abs(Date.now() / 1000 - Number(timestamp)) > toleranceSeconds) return false

  const signedContent = Buffer.concat([Buffer.from(`${id}.${timestamp}.`), Buffer.from(rawBody)])
  const keys = publicKeys.map((key) =>
    createPublicKey({
      key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(key, 'base64').toString('base64url') },
      format: 'jwk',
    }),
  )

  for (const entry of signatureHeader.split(' ')) {
    const [version, signature = ''] = entry.split(',', 2)
    if (version !== 'v1a') continue

    const signatureBytes = Buffer.from(signature, 'base64')
    if (signatureBytes.length !== 64) continue

    if (keys.some((key) => verify(null, signedContent, key, signatureBytes))) return true
  }

  return false
}

// Verifies a delivery and applies it at most once.
//
// applyOnce(webhookId, event) must, in ONE database transaction, insert
// webhookId into a table with a UNIQUE constraint and apply the event only if
// that insert added a row. Credit money idempotently on
// (data.account.id, data.transaction.ref) as well. Marking the id as seen
// before the effect is committed would lose the event if your process crashes
// in between, because wrapbiz will not redeliver an event you already
// answered 2xx for.
//
// Resolves to the HTTP status to reply with: 401 for a bad signature or a
// timestamp outside the tolerance, 400 for a non-JSON body, otherwise 200
// (also for a redelivered webhook-id, so delivery stops).
export async function handleWrapbizWebhook(rawBody, headers, publicKeys, applyOnce, toleranceSeconds = 300) {
  if (!verifyWrapbizWebhook(rawBody, headers, publicKeys, toleranceSeconds)) return 401

  let event
  try {
    event = JSON.parse(Buffer.from(rawBody).toString('utf8'))
  } catch {
    return 400
  }
  if (event === null || typeof event !== 'object') return 400

  await applyOnce(headers['webhook-id'], event)
  return 200
}
