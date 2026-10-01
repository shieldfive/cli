import { hkdfSync } from 'node:crypto'

// Argon2id master-secret derivation, byte-identical to
// @shieldfive/crypto/kdf/argon2id deriveMasterSecret (the web's and the
// vault's reference implementation): libsodium presets, Argon2id v0x13,
// parallelism 1, 32-byte output, and salts longer than 16 bytes compressed
// through HKDF-SHA-256 (zero salt, info 'shieldfive/v1/argon2id/salt-compression').
//
// Two backends, same bytes:
//
//  - native `argon2` (an optionalDependency): async, runs on the libuv thread
//    pool so the event loop keeps turning, and several times faster.
//  - @shieldfive/crypto over libsodium WASM: always installed. Used when the
//    native module is missing, which is expected on platforms `argon2` ships no
//    prebuilt binary for (Intel macOS, Windows on ARM) and where compiling it
//    failed. npm drops a failed optional dependency instead of failing the
//    install, so `npm i -g @shieldfive/cli` never hard-fails on it.
//
// Parameters are never reduced on either path. test/argon2.backends.test.mjs
// pins the two backends against each other and against web-produced vectors.

const PRESETS = {
  moderate: { timeCost: 3, memoryCost: 262144 }, // OPSLIMIT/MEMLIMIT_MODERATE (256 MiB)
  sensitive: { timeCost: 4, memoryCost: 1048576 }, // OPSLIMIT/MEMLIMIT_SENSITIVE (1 GiB)
}

let nativePromise
async function loadNative() {
  if (process.env.SF_ARGON2_BACKEND === 'wasm') return null
  nativePromise ??= import('argon2').then(
    (m) => (typeof m.hash === 'function' ? m : m.default ?? null),
    () => null,
  )
  return nativePromise
}

/** 'native' or 'wasm': which backend the next derivation will use. */
export async function argon2Backend() {
  return (await loadNative()) ? 'native' : 'wasm'
}

function validate({ passphrase, salt, preset }) {
  if (typeof passphrase !== 'string' || !passphrase) throw new Error('Passphrase is required')
  if (!(salt instanceof Uint8Array) || salt.length < 16) throw new Error('Argon2id salt must be at least 16 bytes')
  const params = Object.hasOwn(PRESETS, preset) ? PRESETS[preset] : null
  if (!params) throw new Error(`Unsupported Argon2id preset: ${preset}`)
  return params
}

export async function deriveMasterSecret({ passphrase, salt, preset = 'moderate' }) {
  const params = validate({ passphrase, salt, preset })
  const native = await loadNative()
  if (!native) {
    const { deriveMasterSecret: wasmDerive } = await import('@shieldfive/crypto/kdf/argon2id')
    const { masterSecret } = await wasmDerive({ passphrase, salt, preset })
    return { masterSecret, salt, preset }
  }
  const usableSalt = salt.length === 16 ? Buffer.from(salt) : Buffer.from(hkdfSync(
    'sha256', salt, Buffer.alloc(32), 'shieldfive/v1/argon2id/salt-compression', 16,
  ))
  const input = Buffer.from(passphrase, 'utf8')
  try {
    const masterSecret = await native.hash(input, {
      ...params, salt: usableSalt, type: native.argon2id, version: 0x13,
      parallelism: 1, hashLength: 32, raw: true,
    })
    return { masterSecret, salt, preset } // a Buffer, i.e. a Uint8Array the caller zeroes
  } finally { input.fill(0); usableSalt.fill(0) }
}
