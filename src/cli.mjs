#!/usr/bin/env node
// ShieldFive CLI (`sf`) — scaffold.
//
//   sf encrypt <folder>          encrypt each file locally (verified core demo)
//   sf push <folder>             login -> unlock -> encrypt -> upload once
//   sf sync <folder> [--watch]   keep the folder mirrored into your vault
//
// The offline crypto chain (unlock -> identity -> encrypt) is VERIFIED
// (`npm test`), and the full upload pipeline (direct + multipart) is wired and
// tested. Configure the live commands with env vars (see README) and run them
// against your own ShieldFive account.

import { webcrypto } from 'node:crypto'
import { readFile, readdir, stat } from 'node:fs/promises'
import { join } from 'node:path'

import { deriveVaultIdentity, encryptFileForVault } from './sfCrypto.mjs'

function usage() {
  process.stdout.write(
    [
      'sf <command>',
      '',
      '  encrypt <folder>            encrypt each file in <folder> locally (verified core)',
      '  push <folder>               login -> unlock -> encrypt -> upload to your vault',
      '  sync <folder> [--watch]     mirror new/changed files into your vault',
      '                              [--interval=<seconds>]  poll interval for --watch (default 5)',
      '  --help',
      '',
      'push / sync read: SF_API_BASE_URL, SF_SUPABASE_URL, SF_SUPABASE_ANON_KEY,',
      '                  SF_EMAIL, SF_PASSWORD, [SF_VAULT_PASSWORD]',
      '',
    ].join('\n') + '\n',
  )
}

async function* filesIn(folder) {
  for (const name of await readdir(folder)) {
    const path = join(folder, name)
    const info = await stat(path)
    if (info.isFile()) yield { name, path, size: info.size }
  }
}

// Demonstrates the verified encryption end to end with an EPHEMERAL identity.
async function cmdEncrypt(folder) {
  const identity = await deriveVaultIdentity(
    webcrypto.getRandomValues(new Uint8Array(32)),
  )
  for await (const { name, path } of filesIn(folder)) {
    const bytes = new Uint8Array(await readFile(path))
    const { encryptedBlob, fileId } = await encryptFileForVault(
      bytes,
      identity.mlKemPublicKey,
    )
    process.stdout.write(
      `encrypted ${name}  ->  fileId ${Buffer.from(fileId).toString('hex')}  ` +
        `(${encryptedBlob.size} bytes ciphertext)\n`,
    )
  }
}

function readLiveConfig() {
  const e = process.env
  const required = {
    apiBaseUrl: e.SF_API_BASE_URL,
    supabaseUrl: e.SF_SUPABASE_URL,
    anonKey: e.SF_SUPABASE_ANON_KEY,
    email: e.SF_EMAIL,
    password: e.SF_PASSWORD,
  }
  const missing = Object.entries(required)
    .filter(([, v]) => !v)
    .map(([k]) => k)
  if (missing.length) {
    throw new Error(
      'this command needs env vars SF_API_BASE_URL, SF_SUPABASE_URL, ' +
        'SF_SUPABASE_ANON_KEY, SF_EMAIL, SF_PASSWORD (and optionally ' +
        `SF_VAULT_PASSWORD). Missing: ${missing.join(', ')}`,
    )
  }
  return { ...required, vaultPassword: e.SF_VAULT_PASSWORD || e.SF_PASSWORD }
}

// Sign in (Supabase -> Bearer) then fetch + unlock the vault root key. Shared by
// `push` and `sync`. Network deps are imported lazily so `sf encrypt` runs
// without @supabase/supabase-js.
async function authAndUnlock(cfg) {
  const { signIn } = await import('./auth.mjs')
  const { fetchAndUnlockVault } = await import('./vault.mjs')

  process.stderr.write('signing in…\n')
  const { accessToken } = await signIn({
    supabaseUrl: cfg.supabaseUrl,
    anonKey: cfg.anonKey,
    email: cfg.email,
    password: cfg.password,
  })

  process.stderr.write('unlocking vault…\n')
  const rootKey = await fetchAndUnlockVault({
    apiBaseUrl: cfg.apiBaseUrl,
    accessToken,
    password: cfg.vaultPassword,
  })
  return { accessToken, rootKey }
}

// login -> unlock -> encrypt -> upload every file in the folder, once.
async function cmdPush(folder) {
  const cfg = readLiveConfig()
  const { uploadFile } = await import('./upload.mjs')
  const { accessToken, rootKey } = await authAndUnlock(cfg)

  for await (const { name, path, size } of filesIn(folder)) {
    await uploadFile({
      apiBaseUrl: cfg.apiBaseUrl,
      accessToken,
      rootKey,
      name,
      path,
      size,
    })
    process.stdout.write(`pushed ${name}\n`)
  }
}

// login -> unlock -> mirror new/changed files into the vault, once or on a loop.
async function cmdSync(folder, { watch, intervalMs }) {
  const cfg = readLiveConfig()
  const { uploadFile } = await import('./upload.mjs')
  const { runSync } = await import('./sync.mjs')

  await runSync({
    cfg,
    folder,
    watch,
    intervalMs,
    authAndUnlock,
    uploadFn: uploadFile,
  })
}

// Minimal parse: first non-flag arg after the command is the positional; --flag
// and --flag=value are collected. Enough for `sf sync <folder> --watch
// --interval=10`.
function parseArgs(argv) {
  const positionals = []
  const flags = {}
  for (const token of argv) {
    if (token.startsWith('--')) {
      const [key, value] = token.slice(2).split('=')
      flags[key] = value === undefined ? true : value
    } else {
      positionals.push(token)
    }
  }
  return { positionals, flags }
}

const argv = process.argv.slice(2)
const cmd = argv[0]

async function main() {
  const { positionals, flags } = parseArgs(argv.slice(1))
  const folder = positionals[0]

  if (!cmd || cmd === '--help' || cmd === '-h') {
    usage()
  } else if (cmd === 'encrypt') {
    if (!folder) throw new Error('encrypt needs a <folder>')
    await cmdEncrypt(folder)
  } else if (cmd === 'push') {
    if (!folder) throw new Error('push needs a <folder>')
    await cmdPush(folder)
  } else if (cmd === 'sync') {
    if (!folder) throw new Error('sync needs a <folder>')
    const intervalSec = flags.interval ? Number(flags.interval) : 5
    if (!Number.isFinite(intervalSec) || intervalSec <= 0) {
      throw new Error('--interval must be a positive number of seconds')
    }
    await cmdSync(folder, {
      watch: Boolean(flags.watch),
      intervalMs: Math.round(intervalSec * 1000),
    })
  } else {
    usage()
    process.exitCode = 1
  }
}

main().catch((err) => {
  process.stderr.write(`error: ${err.message}\n`)
  process.exit(1)
})
