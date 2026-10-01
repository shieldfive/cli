// Test helper: open a CLI upload the way the web app and the reference decryptor
// do, from nothing but what the server stores and the owner's root key.
//
//   - csk_wrapped / csk_iv from the create-upload-session body, unwrapped under
//     the root key (the CLI uploads to the vault root);
//   - the owner's ML-KEM secret key, derived from the root key exactly as
//     web utils/pqIdentity.ts derives it;
//   - @shieldfive/crypto's autoDecryptBlob over the stored object (all parts,
//     in part order).
//
// Nothing here imports the CLI's own encryption code.

import { createHmac } from 'node:crypto'

import { autoDecryptBlob } from '@shieldfive/crypto'
import { parseHeader } from '@shieldfive/crypto/format'
import { createIdentity } from '@shieldfive/crypto/identity'

export function concat(parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let off = 0
  for (const p of parts) {
    out.set(p, off)
    off += p.length
  }
  return out
}

export function uuidBytes(id) {
  return new Uint8Array(Buffer.from(id.replace(/-/g, ''), 'hex'))
}

async function unwrapUnderRoot(rootKey, wrappedB64, ivB64) {
  const { webcrypto } = await import('node:crypto')
  const k = await webcrypto.subtle.importKey('raw', rootKey, 'AES-GCM', false, ['decrypt'])
  return new Uint8Array(
    await webcrypto.subtle.decrypt(
      { name: 'AES-GCM', iv: Buffer.from(ivB64, 'base64') },
      k,
      Buffer.from(wrappedB64, 'base64'),
    ),
  )
}

/** Decrypt the stored object; returns { plaintext, header }. */
export async function referenceDecrypt({ stored, rootKey, cskWrapped, cskIv }) {
  const envelopeKey = await unwrapUnderRoot(rootKey, cskWrapped, cskIv)
  // userId is metadata only; the web passes its own placeholder.
  const identity = await createIdentity({ userId: 'web-placeholder', masterSecret: rootKey })
  const out = await autoDecryptBlob({
    blob: new Blob([stored]),
    envelopeKey,
    recipientSecretKey: identity.mlKemSecretKey,
  })
  const blob = out?.blob ?? out
  return { plaintext: new Uint8Array(await blob.arrayBuffer()), header: parseHeader(stored) }
}

/**
 * The suite-0x03 upload proof, built independently from the server's verifier
 * description: base64([0x03][0x03] || HMAC-SHA256(proofKey, [0x03][0x03] ||
 * header || frame_0)).
 */
export function independentV3Proof(proofKeyHex, part0) {
  const h = parseHeader(part0)
  const frameLen = new DataView(part0.buffer, part0.byteOffset).getUint32(h.headerLength, false)
  const covered = part0.subarray(0, h.headerLength + 4 + frameLen)
  const mac = createHmac('sha256', Buffer.from(proofKeyHex, 'hex'))
    .update(Uint8Array.of(3, 3))
    .update(covered)
    .digest()
  return Buffer.concat([Buffer.from([3, 3]), mac]).toString('base64')
}
