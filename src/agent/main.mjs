// ShieldFive CLI — agent entry point.
//
// `sf login` starts this as a detached child and passes it one JSON handoff on
// stdin: the session, the root key and the backend config. Stdin is used
// because it is the one channel between the two processes that does not appear
// in `ps` output or in /proc/<pid>/environ. This process never sees the
// password, and it never reads SF_PASSWORD.

import { homedir } from 'node:os'

import { uploadFile } from '../upload.mjs'
import { deviceId, socketPath } from './paths.mjs'
import { createAgent } from './server.mjs'

const MAX_HANDOFF_BYTES = 64_000

export async function readHandoff(stream) {
  let raw = ''
  for await (const chunk of stream) {
    raw += chunk
    if (raw.length > MAX_HANDOFF_BYTES) throw new Error('Agent handoff is too large.')
  }

  let h
  try {
    h = JSON.parse(raw)
  } catch {
    throw new Error('Agent handoff is not valid JSON.')
  }

  const rootKey = new Uint8Array(Buffer.from(String(h?.rootKey ?? ''), 'base64'))
  if (rootKey.length !== 32) throw new Error('Agent handoff does not carry a 32-byte root key.')

  for (const field of ['apiBaseUrl', 'supabaseUrl', 'anonKey']) {
    if (typeof h?.config?.[field] !== 'string' || !h.config[field]) {
      throw new Error(`Agent handoff is missing config.${field}.`)
    }
  }

  return {
    session: h.session,
    rootKey,
    config: h.config,
    idleMs: Number.isFinite(h.idleMs) && h.idleMs > 0 ? h.idleMs : undefined,
  }
}

export async function runAgent({ stdin = process.stdin, stdout = process.stdout, env = process.env } = {}) {
  stdin.setEncoding('utf8')
  const handoff = await readHandoff(stdin)
  const home = homedir()
  const socket = socketPath({ env })

  const agent = createAgent({
    ...handoff,
    socket,
    home,
    device: await deviceId(home),
    uploadFile,
    // Leave a moment for the reply to a lock or logout request to flush. The
    // timer is unref'd, so if nothing else is pending the process exits sooner.
    onStop: () => setTimeout(() => process.exit(0), 250).unref(),
  })
  handoff.rootKey.fill(0)

  await agent.start()
  for (const signal of ['SIGTERM', 'SIGINT', 'SIGHUP']) {
    process.on(signal, () => agent.stop(`signal ${signal}`))
  }

  stdout.write(JSON.stringify({ ready: true, pid: process.pid, socket }) + '\n')
}
