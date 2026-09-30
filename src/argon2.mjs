import { hkdfSync } from 'node:crypto'
import { hash, argon2id } from 'argon2'

// Same libsodium presets and salt compression as @shieldfive/crypto. Native
// async hashing runs outside the Node event loop; parameters are never reduced.
export async function deriveMasterSecret({ passphrase, salt, preset = 'moderate' }) {
  if (typeof passphrase !== 'string' || !passphrase) throw new Error('Passphrase is required')
  if (!(salt instanceof Uint8Array) || salt.length < 16) throw new Error('Argon2id salt must be at least 16 bytes')
  const params = preset === 'moderate' ? { timeCost: 3, memoryCost: 262144 } :
    preset === 'sensitive' ? { timeCost: 4, memoryCost: 1048576 } : null
  if (!params) throw new Error(`Unsupported Argon2id preset: ${preset}`)
  const usableSalt = salt.length === 16 ? Buffer.from(salt) : Buffer.from(hkdfSync(
    'sha256', salt, Buffer.alloc(32), 'shieldfive/v1/argon2id/salt-compression', 16,
  ))
  const input = Buffer.from(passphrase, 'utf8')
  try {
    const masterSecret = await hash(input, {
      ...params, salt: usableSalt, type: argon2id, version: 0x13,
      parallelism: 1, hashLength: 32, raw: true,
    })
    return { masterSecret, salt, preset }
  } finally { input.fill(0); usableSalt.fill(0) }
}
