// The native and WASM Argon2id backends must produce the same bytes as the
// reference @shieldfive/crypto deriveMasterSecret the web wraps vaults with.
// If `argon2` failed to install (it is optional), only the WASM half runs.
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { deriveMasterSecret as reference } from '@shieldfive/crypto/kdf/argon2id'

import { argon2Backend, deriveMasterSecret } from '../src/argon2.mjs'

const hex = (u8) => Buffer.from(u8).toString('hex')

test('the native backend is used when installed', async () => {
  let installed = true
  try { await import('argon2') } catch { installed = false }
  assert.equal(await argon2Backend(), installed ? 'native' : 'wasm')
})

for (const saltLength of [16, 32]) {
  test(`moderate preset, ${saltLength}-byte salt: CLI derivation == @shieldfive/crypto`, async () => {
    const salt = new Uint8Array(saltLength).fill(0x2a)
    const passphrase = 'pässwörd with ünïcode ✓'
    const [ours, ref] = await Promise.all([
      deriveMasterSecret({ passphrase, salt, preset: 'moderate' }),
      reference({ passphrase, salt, preset: 'moderate' }),
    ])
    assert.equal(hex(ours.masterSecret), hex(ref.masterSecret))
  })
}

test('sensitive preset (1 GiB): CLI derivation == @shieldfive/crypto', { timeout: 300_000 }, async () => {
  const salt = new Uint8Array(16).fill(0x11)
  const passphrase = 'sensitive preset interop'
  const ours = await deriveMasterSecret({ passphrase, salt, preset: 'sensitive' })
  const ref = await reference({ passphrase, salt, preset: 'sensitive' })
  assert.equal(hex(ours.masterSecret), hex(ref.masterSecret))
})

test('forcing the WASM fallback yields the pinned web vector', { timeout: 120_000 }, () => {
  // A fresh process, so the backend choice is not cached from this one.
  const script = `
    import { argon2Backend } from ${JSON.stringify(fileURLToPath(new URL('../src/argon2.mjs', import.meta.url)))}
    import { deriveLoginSecret } from ${JSON.stringify(fileURLToPath(new URL('../src/loginSecret.mjs', import.meta.url)))}
    const backend = await argon2Backend()
    const secret = await deriveLoginSecret({ password: 'correct horse battery staple 42', authSalt: Buffer.alloc(32, 7).toString('base64') })
    process.stdout.write(JSON.stringify({ backend, secret }))
  `
  const out = spawnSync(process.execPath, ['--input-type=module', '-e', script], {
    env: { ...process.env, SF_ARGON2_BACKEND: 'wasm' }, encoding: 'utf8',
  })
  assert.equal(out.status, 0, out.stderr)
  assert.deepEqual(JSON.parse(out.stdout), {
    backend: 'wasm', secret: '-3MAPAD6FFMypDmTdLMY0ivfscMAlhyFK5aj5-1c8N8',
  })
})

test('unsupported presets and short salts are refused', async () => {
  await assert.rejects(deriveMasterSecret({ passphrase: 'x', salt: new Uint8Array(16), preset: 'interactive' }), /Unsupported/)
  await assert.rejects(deriveMasterSecret({ passphrase: 'x', salt: new Uint8Array(8) }), /at least 16/)
  await assert.rejects(deriveMasterSecret({ passphrase: 'x', salt: new Uint8Array(16), preset: 'toString' }), /Unsupported/)
})
