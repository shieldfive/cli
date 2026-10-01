// Regenerate test/vectors/v3-upload.json: what `sf push` stores for a known
// root key, row id, name and plaintext, produced by the CLI's own writer.
//
// Encryption is randomised (envelope key, ML-KEM encapsulation, IVs, salts), so
// these are DECRYPT vectors: any client given the root key must recover the
// name and the plaintext from the stored fields, and must find the row id in
// the header. The ML-KEM public-key fingerprint is deterministic and pins the
// identity derivation the web app uses (utils/pqIdentity.ts).
//
//   node scripts/generate-vectors.mjs

import { createHash } from 'node:crypto'
import { writeFileSync } from 'node:fs'

import { encryptNameV6 } from '@shieldfive/crypto/vault'

import {
  base64ToBytes,
  bytesToBase64,
  encryptMetadataV4,
  encryptPartsV3,
  generateRandomKeyB64,
  hashMetadataV4,
  uuidToBytes,
  vaultMlKemPublicKey,
  wrapKeyB64,
} from '../src/uploadCrypto.mjs'

const rootKey = new Uint8Array(32).map((_, i) => (i * 7 + 3) & 0xff)
const rowId = '6b1d3f2a-9c4e-4a7b-8e2d-1f0c5a9b3e74'
const name = 'Q3 tax return – signed.pdf'
const chunkSize = 16
const plaintext = new TextEncoder().encode('ShieldFive CLI v3 vector: four chunks, last one short.')

const rootKeyB64 = bytesToBase64(rootKey)
const csk = generateRandomKeyB64()
const cskEnvelope = wrapKeyB64({ wrappingKeyB64: rootKeyB64, keyToWrapB64: csk })
const recipientPublicKey = await vaultMlKemPublicKey(rootKey)

async function* chunks() {
  for (let i = 0; i < plaintext.length; i += chunkSize) yield plaintext.slice(i, i + chunkSize)
}
const parts = []
for await (const part of encryptPartsV3({
  plaintextChunks: chunks(),
  plaintextSize: plaintext.length,
  chunkSize,
  envelopeKey: base64ToBytes(csk),
  fileId: uuidToBytes(rowId),
  recipientPublicKey,
})) {
  parts.push(bytesToBase64(part))
}

const vector = {
  description:
    'sf push output (cipher_version 3, suite 0x03, v1 wire format) for a vault-root upload. ' +
    'Decrypt with the root key only: unwrap csk_wrapped under the root key (AES-GCM), derive the ML-KEM ' +
    'secret key with createIdentity({ masterSecret: rootKey }), decrypt the concatenated parts. The header ' +
    'file_id must equal rowId. Names: name_encrypted (v4) opens without a row id; nameEncryptedV6 only with rowId.',
  generatedBy: '@shieldfive/cli scripts/generate-vectors.mjs',
  rootKey: rootKeyB64,
  rowId,
  name,
  chunkSize,
  plaintext: bytesToBase64(plaintext),
  mlKemPublicKeySha256: createHash('sha256').update(recipientPublicKey).digest('hex'),
  cipherVersion: 3,
  cskWrapped: cskEnvelope.wrapped,
  cskIv: cskEnvelope.iv,
  parts,
  nameEncrypted: JSON.stringify(await encryptMetadataV4(name, rootKeyB64)),
  nameEncryptedV6: JSON.stringify(await encryptNameV6({ name, folderKey: rootKey, rowId })),
  nameHash: hashMetadataV4(name.toLowerCase(), rootKeyB64),
}
writeFileSync(new URL('../test/vectors/v3-upload.json', import.meta.url), `${JSON.stringify(vector, null, 2)}\n`)
console.log('wrote test/vectors/v3-upload.json')
