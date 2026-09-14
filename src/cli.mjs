#!/usr/bin/env node
// ShieldFive CLI (`sf`).
//
//   sf encrypt <folder>          encrypt each file locally (verified core demo)
//   sf login [--idle=<hours>]    sign in once; an agent holds the session in memory
//   sf status                    is an agent running, and for which account
//   sf logout [--everywhere]     revoke the session and stop the agent
//   sf push <folder>             encrypt and upload every file, once
//   sf sync <folder> [--watch]   upload new and changed files
//   sf verify <file>...          is each file safely stored in your vault
//
// push and sync use a running agent when there is one. When SF_EMAIL and
// SF_PASSWORD are set they sign in from those instead, exactly as before, so a
// script written for one account is never quietly redirected to an agent
// signed in as another. See docs/agent-design.md.

import { webcrypto } from 'node:crypto'
import { readFile, readdir, stat } from 'node:fs/promises'
import { join, resolve } from 'node:path'

import { promptHidden, promptLine } from './prompt.mjs'
import { deriveVaultIdentity, encryptFileForVault } from './sfCrypto.mjs'

function usage() {
  process.stdout.write(
    [
      'sf <command>',
      '',
      '  login [--idle=<hours>]      sign in once and start an agent (default: locks after 8 h without use)',
      '  status                      show whether an agent is running',
      '  logout [--everywhere]       revoke the session and stop the agent',
      '                              --everywhere also signs out your browser and phone',
      '  push <folder>               encrypt and upload every file in <folder>',
      '  sync <folder> [--watch]     upload new and changed files',
      '                              [--interval=<seconds>]  poll interval for --watch (default 5)',
      '  verify <file>...            report whether each file is safely in your vault',
      '  encrypt <folder>            encrypt each file locally, upload nothing',
      '  --help',
      '',
      'After sf login, push / sync / verify go through the agent and need nothing',
      'in the environment. Without an agent, or when SF_EMAIL and SF_PASSWORD are',
      'set, push and sync sign in from those [SF_VAULT_PASSWORD if your vault',
      'password differs]. SF_API_BASE_URL, SF_SUPABASE_URL, SF_SUPABASE_ANON_KEY',
      'default to ShieldFive (override only for a development backend).',
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

// ShieldFive's PUBLIC client configuration — the same values the website ships
// to every browser and the mobile app embeds. The anon key is a Supabase JWT
// with role=anon, gated by row-level security; it is designed to be public.
// All three default here and are overridable via env for development or a
// staging backend, so a normal user only needs SF_EMAIL + SF_PASSWORD.
const DEFAULTS = {
  apiBaseUrl: 'https://shieldfive.com',
  supabaseUrl: 'https://dskbmjpanehckhqzkclp.supabase.co',
  anonKey:
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImRza2JtanBhbmVoY2tocXprY2xwIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzAxMTc3MzEsImV4cCI6MjA4NTY5MzczMX0.AK7K8tyrAWFWgfaa6vvTveqmKiMrL2nY1m7qS9TII9U',
}

function backendConfig() {
  const e = process.env
  return {
    apiBaseUrl: e.SF_API_BASE_URL || DEFAULTS.apiBaseUrl,
    supabaseUrl: e.SF_SUPABASE_URL || DEFAULTS.supabaseUrl,
    anonKey: e.SF_SUPABASE_ANON_KEY || DEFAULTS.anonKey,
  }
}

function envCredentialsSet() {
  return Boolean(process.env.SF_EMAIL && process.env.SF_PASSWORD)
}

function readLiveConfig() {
  const e = process.env
  const email = e.SF_EMAIL
  const password = e.SF_PASSWORD
  const missing = []
  if (!email) missing.push('SF_EMAIL')
  if (!password) missing.push('SF_PASSWORD')
  if (missing.length) {
    throw new Error(
      `this command needs your ShieldFive account: run sf login, or set ` +
        `${missing.join(' and ')}. (SF_API_BASE_URL, SF_SUPABASE_URL, and ` +
        'SF_SUPABASE_ANON_KEY default to ShieldFive; override them only for a ' +
        'development backend.)',
    )
  }
  return {
    ...backendConfig(),
    email,
    password,
    vaultPassword: e.SF_VAULT_PASSWORD || password,
  }
}

// Source a TOTP code for the 2FA step-up: SF_TOTP_CODE if set (handy for
// scripting), otherwise prompt interactively. Only invoked when the account
// actually requires a step-up.
async function readTotpCode() {
  if (process.env.SF_TOTP_CODE) return process.env.SF_TOTP_CODE
  if (!process.stdin.isTTY) {
    throw new Error(
      'Two-factor code required but no terminal is attached. Set SF_TOTP_CODE ' +
        'to your current 6-digit authenticator code.',
    )
  }
  return promptLine('Two-factor code (6 digits): ')
}

// Sign in (Supabase -> Bearer, with 2FA step-up if enabled) then fetch + unlock
// the vault root key. Shared by `push` and `sync`. Network deps are imported
// lazily so `sf encrypt` runs without @supabase/supabase-js.
async function authAndUnlock(cfg) {
  const { signIn } = await import('./auth.mjs')
  const { fetchAndUnlockVault } = await import('./vault.mjs')

  process.stderr.write('signing in…\n')
  const { accessToken } = await signIn({
    supabaseUrl: cfg.supabaseUrl,
    anonKey: cfg.anonKey,
    email: cfg.email,
    password: cfg.password,
    getTotpCode: readTotpCode,
  })

  process.stderr.write('unlocking vault…\n')
  const rootKey = await fetchAndUnlockVault({
    apiBaseUrl: cfg.apiBaseUrl,
    accessToken,
    password: cfg.vaultPassword,
  })
  return { accessToken, rootKey }
}

async function runningAgent() {
  const { agentStatus } = await import('./agent/client.mjs')
  const status = await agentStatus()
  return status?.unlocked ? status : null
}

/**
 * Decide how push and sync authenticate. Environment credentials win when both
 * are set: that is how these commands behaved before the agent existed, and it
 * keeps a script that names an account from being redirected to whichever
 * account the agent happens to hold.
 */
async function chooseAuth() {
  const agent = await runningAgent()
  if (envCredentialsSet()) {
    if (agent) {
      process.stderr.write(
        `SF_EMAIL and SF_PASSWORD are set, so this signs in with them rather than ` +
          `through the running agent (account ${agent.account}). Unset them to use the agent.\n`,
      )
    }
    return { agent: null }
  }
  return { agent }
}

// Start the agent as a detached child and hand it the session over stdin.
async function launchAgent({ session, rootKey, config, idleMs }) {
  const { spawn } = await import('node:child_process')
  const { fileURLToPath } = await import('node:url')

  // Only what the agent needs to find its home directory and reach the
  // network. Not SF_PASSWORD, not SF_TOTP_CODE, and nothing else the shell
  // happened to export.
  const env = {}
  for (const name of [
    'PATH', 'HOME', 'USER', 'LOGNAME', 'LANG',
    'SF_API_BASE_URL', 'SF_SUPABASE_URL', 'SF_SUPABASE_ANON_KEY',
    'HTTPS_PROXY', 'HTTP_PROXY', 'NO_PROXY', 'NODE_EXTRA_CA_CERTS',
  ]) {
    if (process.env[name]) env[name] = process.env[name]
  }

  const child = spawn(process.execPath, [fileURLToPath(import.meta.url), '__agent'], {
    detached: true,
    stdio: ['pipe', 'pipe', 'pipe'],
    env,
  })

  const ready = await new Promise((resolveReady, reject) => {
    let out = ''
    let err = ''
    const timer = setTimeout(() => {
      child.kill()
      reject(new Error(`The agent did not start within 15 s.${err ? ` ${err.trim()}` : ''}`))
    }, 15_000)

    child.stdout.setEncoding('utf8')
    child.stderr.setEncoding('utf8')
    child.stdout.on('data', (chunk) => {
      out += chunk
      const newline = out.indexOf('\n')
      if (newline === -1) return
      clearTimeout(timer)
      try {
        resolveReady(JSON.parse(out.slice(0, newline)))
      } catch {
        reject(new Error('The agent sent an unreadable start signal.'))
      }
    })
    child.stderr.on('data', (chunk) => {
      err += chunk
    })
    child.on('exit', (code) => {
      clearTimeout(timer)
      reject(new Error(`The agent exited before it was ready (code ${code}).${err ? ` ${err.trim()}` : ''}`))
    })

    child.stdin.end(
      JSON.stringify({
        session,
        rootKey: Buffer.from(rootKey).toString('base64'),
        config,
        idleMs,
      }),
    )
  })

  child.stdout.destroy()
  child.stderr.destroy()
  child.unref()
  return ready
}

function readIdle(flags) {
  if (flags.idle === true) {
    throw new Error('--idle needs a value: sf login --idle=<hours>')
  }
  const hours = flags.idle === undefined ? 8 : Number(flags.idle)
  if (!Number.isFinite(hours) || hours * 60 < 1 || hours > 168) {
    throw new Error('--idle must be a number of hours from 1 minute (0.0167) to 168')
  }
  return { hours, ms: Math.round(hours * 3_600_000) }
}

async function cmdLogin(flags) {
  const idle = readIdle(flags)

  const existing = await runningAgent()
  if (existing) {
    process.stdout.write(
      `Already logged in (account ${existing.account}, agent pid ${existing.pid}). ` +
        'Run sf logout first to use another account.\n',
    )
    return
  }
  if (!process.stdin.isTTY) {
    throw new Error(
      'sf login needs an interactive terminal. It prompts for your password ' +
        'instead of reading it from the environment.',
    )
  }

  const cfg = backendConfig()
  const email = process.env.SF_EMAIL || (await promptLine('Email: ')).trim()
  const password = await promptHidden('Password: ')
  const vaultPassword =
    (await promptHidden('Vault password (press Enter if it is the same): ')) || password

  const { signIn } = await import('./auth.mjs')
  const { fetchAndUnlockVault } = await import('./vault.mjs')

  process.stderr.write('signing in…\n')
  const session = await signIn({ ...cfg, email, password, getTotpCode: readTotpCode })

  process.stderr.write('unlocking vault…\n')
  const rootKey = await fetchAndUnlockVault({
    apiBaseUrl: cfg.apiBaseUrl,
    accessToken: session.accessToken,
    password: vaultPassword,
  })

  const started = await launchAgent({ session, rootKey, config: cfg, idleMs: idle.ms })
  rootKey.fill(0)

  process.stdout.write(
    `Logged in as ${email}. The agent (pid ${started.pid}) holds the session in memory ` +
      `only and locks after ${idle.hours} h without an upload, sync or verify. ` +
      'Run sf logout to end it.\n',
  )
}

async function cmdStatus() {
  const status = await runningAgent()
  if (!status) {
    process.stdout.write('Not logged in: no agent is running.\n')
    return
  }
  const totalMinutes = Math.round(status.idleLocksInSec / 60)
  const hours = Math.floor(totalMinutes / 60)
  const minutes = totalMinutes % 60
  process.stdout.write(
    `Logged in (account ${status.account}). Agent pid ${status.pid}; locks after ` +
      `${hours} h ${minutes} min without an upload, sync or verify.\n`,
  )
}

async function cmdLogout(flags) {
  const { AgentUnavailableError, request } = await import('./agent/client.mjs')
  const everywhere = flags.everywhere === true
  let result
  try {
    result = await request('logout', { everywhere }, { timeoutMs: 15_000 })
  } catch (err) {
    if (err instanceof AgentUnavailableError) {
      process.stdout.write('Not logged in: no agent is running.\n')
      return
    }
    throw err
  }

  if (result.sessionRevoked) {
    process.stdout.write(
      everywhere
        ? 'Logged out. Every ShieldFive session on this account was signed out, including your browser and phone.\n'
        : 'Logged out. The session was revoked on the server.\n',
    )
    return
  }

  // Both failures leave the key wiped here. They differ in what is known about
  // the session, and in what the user can do about it.
  process.exitCode = 1
  if (result.revokeStatus === 0) {
    process.stdout.write(
      'Logged out on this machine, but the server could not be reached, so the ' +
        'session is still valid there. Once you are online, run sf login and then ' +
        'sf logout --everywhere to end it.\n',
    )
  } else {
    process.stdout.write(
      `Logged out on this machine, but the server did not accept the sign-out ` +
        `(HTTP ${result.revokeStatus}). The session may already have ended. To be ` +
        'certain, run sf login and then sf logout --everywhere, which ends every ' +
        'session on this account, including your browser.\n',
    )
  }
}

// login -> unlock -> encrypt -> upload every file in the folder, once.
async function cmdPush(folder) {
  const { agent } = await chooseAuth()
  if (agent) {
    const { request } = await import('./agent/client.mjs')
    process.stderr.write(`pushing to account ${agent.account} through the agent\n`)
    let differs = 0
    for await (const { name, path } of filesIn(resolve(folder))) {
      const result = await request('upload', { path }, { timeoutMs: 0 })
      if (result.matchesFileNow) {
        process.stdout.write(`pushed ${name}\n`)
      } else {
        differs++
        process.stdout.write(
          `pushed ${name}, but it changed while uploading: the vault holds the ` +
            'version that was read, not the file as it is now\n',
        )
      }
    }
    // Non-zero so a script does not treat a file whose current contents are not
    // in the vault as pushed.
    if (differs) process.exitCode = 2
    return
  }

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

async function syncViaAgent(folder, { watch, intervalMs }, agent) {
  const { AgentUnavailableError, request } = await import('./agent/client.mjs')
  const controller = new AbortController()
  const onSigint = () => {
    process.stderr.write('\nstopping…\n')
    controller.abort()
  }
  if (watch) process.on('SIGINT', onSigint)
  process.stderr.write(`syncing to account ${agent.account} through the agent\n`)

  try {
    do {
      let summary
      try {
        summary = await request('sync', { folder }, { timeoutMs: 0 })
      } catch (err) {
        if (err instanceof AgentUnavailableError || err.code === 'locked') {
          throw new Error('The agent was locked or logged out. Run sf login to continue.')
        }
        throw err
      }
      for (const e of summary.errors) process.stdout.write(`failed ${e.path}: ${e.message}\n`)
      process.stderr.write(
        `pass: ${summary.uploaded} synced, ${summary.skipped} unchanged` +
          (summary.changed ? `, ${summary.changed} changed while uploading (uploaded again on the next pass)` : '') +
          (summary.failed ? `, ${summary.failed} failed` : '') +
          '\n',
      )
      if (!watch || controller.signal.aborted) break
      await new Promise((r) => {
        const timer = setTimeout(r, intervalMs)
        controller.signal.addEventListener(
          'abort',
          () => {
            clearTimeout(timer)
            r()
          },
          { once: true },
        )
      })
    } while (!controller.signal.aborted)
  } finally {
    if (watch) process.off('SIGINT', onSigint)
  }
}

// login -> unlock -> mirror new/changed files into the vault, once or on a loop.
async function cmdSync(folder, { watch, intervalMs }) {
  const { agent } = await chooseAuth()
  if (agent) return syncViaAgent(resolve(folder), { watch, intervalMs }, agent)

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

const STATE_LABELS = {
  verified: 'backed up',
  missing: 'NOT confirmed',
  changed_since_upload: 'changed since upload',
  not_in_ledger: 'no upload record',
  unreadable: 'unreadable',
}

async function cmdVerify(paths) {
  if (!paths.length) throw new Error('verify needs at least one file')
  const { request } = await import('./agent/client.mjs')
  const results = await request('verify', { paths: paths.map((p) => resolve(p)) }, { timeoutMs: 0 })

  for (const r of results) {
    const label = STATE_LABELS[r.state] ?? r.state
    const note = r.matchedPath ? `  (same bytes as ${r.matchedPath})` : r.reason ? `  (${r.reason})` : ''
    process.stdout.write(`${label.padEnd(22)} ${r.path}${note}\n`)
  }
  // Exit 0 only when every file is confirmed, so a script can gate on it.
  if (!results.every((r) => r.state === 'verified')) process.exitCode = 2
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

  if (cmd === '__agent') {
    // A detached agent outlives the terminal that started it; writing to a
    // closed pipe must not take it down.
    process.stdout.on('error', () => {})
    process.stderr.on('error', () => {})
    const { runAgent } = await import('./agent/main.mjs')
    await runAgent()
  } else if (!cmd || cmd === '--help' || cmd === '-h') {
    usage()
  } else if (cmd === 'login') {
    await cmdLogin(flags)
  } else if (cmd === 'status') {
    await cmdStatus()
  } else if (cmd === 'logout') {
    await cmdLogout(flags)
  } else if (cmd === 'encrypt') {
    if (!folder) throw new Error('encrypt needs a <folder>')
    await cmdEncrypt(folder)
  } else if (cmd === 'push') {
    if (!folder) throw new Error('push needs a <folder>')
    await cmdPush(folder)
  } else if (cmd === 'sync') {
    if (!folder) throw new Error('sync needs a <folder>')
    // `--interval 10` (space-separated) would otherwise parse as a bare flag and
    // quietly become a one-second interval.
    if (flags.interval === true) throw new Error('--interval needs a value: --interval=<seconds>')
    const intervalSec = flags.interval ? Number(flags.interval) : 5
    if (!Number.isFinite(intervalSec) || intervalSec <= 0) {
      throw new Error('--interval must be a positive number of seconds')
    }
    await cmdSync(folder, {
      watch: Boolean(flags.watch),
      intervalMs: Math.round(intervalSec * 1000),
    })
  } else if (cmd === 'verify') {
    await cmdVerify(positionals)
  } else {
    usage()
    process.exitCode = 1
  }
}

main().catch((err) => {
  process.stderr.write(`error: ${err.message}\n`)
  process.exit(1)
})
