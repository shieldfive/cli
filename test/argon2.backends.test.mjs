import assert from 'node:assert/strict'
import { test } from 'node:test'

import { deriveMasterSecret } from '../src/argon2.mjs'
import { deriveLoginSecret } from '../src/loginSecret.mjs'

// Captured from the prior CLI's native Argon2id backend.
for (const [length, byte, passphrase, preset, expected] of [
  [16, 42, 'pässwörd with ünïcode ✓', 'moderate', '51bd511621185f7f20e870fdeefbd92b01751b5095fa0f25ca5d850ee1418168'],
  [32, 42, 'pässwörd with ünïcode ✓', 'moderate', '3d855c1f4adbf2c1374eaad87d8cdcdec3da17700b95d9f085e3dd342f627485'],
  [16, 17, 'sensitive preset interop', 'sensitive', 'f5d176326b49b7a9c78980ab2827abaa42a335f229333c4b05677c814921e54e'],
]) {
  test(`WASM matches native Argon2id for ${preset}, ${length}-byte salt`, async () => {
    const { masterSecret } = await deriveMasterSecret({ passphrase, salt: Buffer.alloc(length, byte), preset })
    assert.equal(Buffer.from(masterSecret).toString('hex'), expected)
  })
}

test('login secret matches the pinned web vector', async () => {
  const secret = await deriveLoginSecret({
    password: 'correct horse battery staple 42',
    authSalt: Buffer.alloc(32, 7).toString('base64'),
  })
  assert.equal(secret, '-3MAPAD6FFMypDmTdLMY0ivfscMAlhyFK5aj5-1c8N8')
})

test('unsupported presets and short salts are refused', async () => {
  await assert.rejects(deriveMasterSecret({ passphrase: 'x', salt: new Uint8Array(16), preset: 'interactive' }), /unknown Argon2id preset/)
  await assert.rejects(deriveMasterSecret({ passphrase: 'x', salt: new Uint8Array(8) }), /at least 16/)
})
