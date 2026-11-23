// Use the vault's Argon2id implementation on every platform. Its WebAssembly
// dependency ships ready to run and requires no npm lifecycle scripts.
export { deriveMasterSecret } from '@shieldfive/crypto/kdf/argon2id'
