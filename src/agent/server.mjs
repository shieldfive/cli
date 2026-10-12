// ShieldFive CLI — the agent process.
//
// Holds one signed-in session and the unwrapped vault root key, in memory only,
// and serves the write-only protocol in protocol.mjs on a Unix domain socket.
// See docs/agent-design.md for why it exists and what it will never do.

import { createHmac, randomUUID } from 'node:crypto'
import { chmod, lstat, open, readFile, rm, stat } from 'node:fs/promises'
import { connect, createServer } from 'node:net'
import { basename, dirname, join } from 'node:path'

import { refreshAccessToken, revokeSession } from '../auth.mjs'
import { MANIFEST_NAME, scanFiles } from '../sync.mjs'
import { appendEntry, classify, deriveLedgerKey, ledgerPath, macFile, readEntries } from './ledger.mjs'
import { ensurePrivateDir, ledgerDir } from './paths.mjs'
import { encode, fail, lineSplitter, ok, parseRequest } from './protocol.mjs'

export const DEFAULT_IDLE_MS = 8 * 60 * 60 * 1000

// Refresh a little before expiry rather than on a 401, so a long upload does
// not start with a token that dies halfway through.
const REFRESH_MARGIN_S = 120
const REFRESH_TIMEOUT_MS = 15_000

// Everything stop() does on the network — refreshing an expired token and
// revoking the session — shares one budget. Keys are wiped before it starts.
const STOP_NETWORK_BUDGET_MS = 5_000

// Only these count as use for the idle lock. A status probe does no work; if it
// counted, a shell prompt or a health check polling `sf status` would keep the
// agent unlocked forever.
const USE_OPS = new Set(['upload', 'sync', 'verify'])

class AgentError extends Error {
  constructor(code, message) {
    super(message)
    this.code = code
  }
}

/** Resolve true when something accepts a connection on `path`. */
export function socketAnswers(path, { timeoutMs = 500 } = {}) {
  return new Promise((resolve) => {
    const s = connect({ path })
    const timer = setTimeout(() => {
      s.destroy()
      resolve(false)
    }, timeoutMs)
    s.on('connect', () => {
      clearTimeout(timer)
      s.destroy()
      resolve(true)
    })
    s.on('error', () => {
      clearTimeout(timer)
      resolve(false)
    })
  })
}

function pidAlive(pid) {
  try {
    process.kill(pid, 0)
    return true
  } catch (err) {
    // EPERM: the process exists but belongs to someone else. Treat it as alive.
    return err.code === 'EPERM'
  }
}

export function createAgent({
  session,
  rootKey,
  config,
  socket,
  home,
  device,
  idleMs = DEFAULT_IDLE_MS,
  uploadFile,
  fetchImpl = fetch,
  now = () => Date.now(),
  log = () => {},
  onStop = () => {},
  stopBudgetMs = STOP_NETWORK_BUDGET_MS,
}) {
  if (!session?.refreshToken) {
    throw new AgentError(
      'no_refresh_token',
      'Sign-in did not produce a refresh token for the stepped-up session, so ' +
        'the agent would stop working within the hour. Run sf login again.',
    )
  }
  if (!session.userId) throw new AgentError('no_account', 'Sign-in did not report an account id.')
  if (!(rootKey instanceof Uint8Array) || rootKey.length !== 32) {
    throw new AgentError('bad_key', 'The agent needs the 32-byte vault root key.')
  }
  if (typeof uploadFile !== 'function') throw new AgentError('bad_config', 'uploadFile is required.')
  if (typeof device !== 'string' || !device) throw new AgentError('bad_config', 'A device id is required.')

  // Copies this agent owns and overwrites on stop.
  const key = Buffer.from(rootKey)
  const ledgerKey = deriveLedgerKey(key)
  const ledgerFile = ledgerPath(ledgerDir(home), session.userId)
  const lockFile = join(dirname(socket), 'agent.lock')
  const lockToken = `${process.pid}:${randomUUID()}`

  let tokens = {
    access: session.accessToken,
    refresh: session.refreshToken,
    expiresAt: session.expiresAt,
  }
  let refreshing = null
  let server = null
  let idleTimer = null
  let inFlight = 0
  let stopping = null
  let idleDeadline = 0

  function touch() {
    clearTimeout(idleTimer)
    idleDeadline = now() + idleMs
    idleTimer = setTimeout(() => {
      if (inFlight > 0) return touch()
      stop('idle')
    }, idleMs)
    idleTimer.unref?.()
  }

  function assertRunning(what) {
    if (stopping) {
      throw new AgentError('locked', `The agent was locked or logged out ${what}.`)
    }
  }

  async function accessToken() {
    assertRunning('before this request could run')
    if (tokens.expiresAt && now() / 1000 < tokens.expiresAt - REFRESH_MARGIN_S) {
      return tokens.access
    }
    // Single flight. Supabase rotates refresh tokens, and presenting the same
    // one twice outside its short grace window revokes the whole session, so
    // three requests arriving at an expired token must share one refresh.
    refreshing ??= refreshAccessToken({
      supabaseUrl: config.supabaseUrl,
      anonKey: config.anonKey,
      refreshToken: tokens.refresh,
      fetchImpl,
      signal: AbortSignal.timeout(REFRESH_TIMEOUT_MS),
    })
      .then((s) => {
        // A refresh that lands after stop() wiped the tokens must not put them
        // back.
        if (!stopping) tokens = { access: s.accessToken, refresh: s.refreshToken, expiresAt: s.expiresAt }
        return s.accessToken
      })
      .catch((err) => {
        if (err.status === 400 || err.status === 401) {
          // Revoked elsewhere, or reused. Nothing this agent holds will work
          // again, so stop instead of failing every request until idle.
          stop('session_revoked', { revoke: false })
          throw new AgentError('session_revoked', 'This session was signed out. Run sf login again.')
        }
        throw err
      })
      .finally(() => {
        refreshing = null
      })
    return refreshing
  }

  async function verifyFileIds(ids) {
    const token = await accessToken()
    const res = await fetchImpl(new URL('/api/mobile/media/verify', config.apiBaseUrl), {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ fileIds: ids }),
    })
    const body = await res.json().catch(() => ({}))
    if (!res.ok) {
      // Fail the whole request rather than reporting everything `missing`. A
      // verification that did not happen is not an answer of either kind.
      throw new AgentError(
        'verify_failed',
        `The server could not verify backups (HTTP ${res.status}${body.code ? `, ${body.code}` : ''}). ` +
          'Nothing was classified.',
      )
    }
    return Array.isArray(body.verified) ? body.verified : []
  }

  async function upload(path) {
    // lstat: a symlink is refused, not followed (and readFileChunks opens with
    // O_NOFOLLOW, so a swap after this check fails too).
    const before = await lstat(path)
    if (!before.isFile()) throw new AgentError('not_a_file', `${path} is not a regular file.`)
    const token = await accessToken()

    // The MAC recorded is the MAC of exactly the bytes that were encrypted, fed
    // in chunk by chunk as uploadFile reads them. Hashing the file before and
    // after the upload cannot see a change that is made and undone while it is
    // being read: both reads agree, and the vault holds something else.
    const hmac = createHmac('sha256', ledgerKey)
    let streamed = 0

    // uploadFile gets its own copy of the key, wiped when it returns. If a
    // logout zeroed the agent's copy while an upload was still wrapping the
    // file's content key, that key would be wrapped under zeros and the file in
    // the vault would never decrypt.
    const uploadKey = Buffer.from(key)
    let fileId
    try {
      ;({ fileId } = await uploadFile({
        apiBaseUrl: config.apiBaseUrl,
        accessToken: token,
        rootKey: uploadKey,
        name: basename(path),
        path,
        size: before.size,
        onPlaintextChunk: (chunk) => {
          hmac.update(chunk)
          streamed += chunk.length
        },
      }))
    } finally {
      uploadKey.fill(0)
    }
    const mac = hmac.digest('hex')

    assertRunning(`while ${path} was uploading. It reached the vault but is not recorded, so sf verify will not vouch for it`)
    if (streamed !== before.size) {
      throw new AgentError(
        'not_recorded',
        `${path} changed size while it was uploading (${before.size} bytes expected, ${streamed} read). ` +
          'It is not recorded as a backup.',
      )
    }

    await appendEntry(
      ledgerFile,
      {
        path,
        size: streamed,
        mtimeMs: before.mtimeMs,
        mac,
        fileId,
        uploadedAt: new Date(now()).toISOString(),
        device,
      },
      { ledgerKey },
    )

    // Whether the file on disk now is the one that was uploaded. It does not
    // change what was recorded, which describes the upload; it tells push and
    // sync whether this file needs uploading again.
    let matchesFileNow = false
    if (!stopping) {
      try {
        matchesFileNow = (await macFile(path, ledgerKey)) === mac
      } catch {
        // Unreadable now: leave it false.
      }
    }
    return { fileId, size: streamed, matchesFileNow, mac }
  }

  async function sync(folder) {
    const st = await stat(folder)
    if (!st.isDirectory()) throw new AgentError('not_a_directory', `${folder} is not a directory.`)

    const files = await scanFiles(folder, { exclude: [MANIFEST_NAME] })
    const { entries } = await readEntries(ledgerFile, { ledgerKey })
    const done = new Set(entries.filter((e) => e.device === device).map((e) => `${e.path}\u0000${e.mac}`))

    let uploaded = 0
    let skipped = 0
    let failed = 0
    let changed = 0
    const errors = []
    for (const f of files) {
      assertRunning(`during sync, after uploading ${uploaded} file(s)`)
      try {
        const mac = await macFile(f.path, ledgerKey)
        if (done.has(`${f.path}\u0000${mac}`)) {
          skipped++
          continue
        }
        const r = await upload(f.path)
        uploaded++
        done.add(`${f.path}\u0000${r.mac}`)
        if (!r.matchesFileNow) changed++
      } catch (err) {
        if (err.code === 'session_revoked' || err.code === 'locked') throw err
        failed++
        errors.push({ path: f.path, message: err.message })
      }
    }
    return { uploaded, skipped, failed, changed, errors }
  }

  async function handle(req) {
    switch (req.op) {
      case 'status':
        return {
          unlocked: !stopping,
          account: session.userId,
          idleLocksInSec: Math.max(0, Math.round((idleDeadline - now()) / 1000)),
          pid: process.pid,
        }
      case 'upload': {
        // The MAC stays in the ledger. A process on the socket has no use for a
        // keyed digest.
        const { fileId, size, matchesFileNow } = await upload(req.args.path)
        return { fileId, size, matchesFileNow }
      }
      case 'sync':
        return sync(req.args.folder)
      case 'verify': {
        const { entries } = await readEntries(ledgerFile, { ledgerKey })
        return classify(req.args.paths, { entries, ledgerKey, verifyFileIds, device })
      }
      case 'lock': {
        const { revoked, status } = await stop('lock')
        return { locked: true, sessionRevoked: revoked, revokeStatus: status }
      }
      case 'logout': {
        const everywhere = req.args.everywhere === true
        const { revoked, status } = await stop('logout', { everywhere })
        return { loggedOut: true, everywhere, sessionRevoked: revoked, revokeStatus: status }
      }
      default:
        throw new AgentError('unknown_op', `Unknown operation ${req.op}.`)
    }
  }

  function onConnection(conn) {
    conn.setEncoding('utf8')
    conn.on('error', () => {})
    let handled = false

    const reply = (message) => {
      if (!conn.destroyed) conn.end(encode(message))
    }

    const feed = lineSplitter(async (line) => {
      // One request per connection. Anything after the first line is ignored.
      if (handled) return
      handled = true

      let req
      try {
        req = parseRequest(line)
      } catch (err) {
        return reply(fail(null, err.code ?? 'bad_request', err.message))
      }
      if (stopping && req.op !== 'status') {
        return reply(fail(req.id, 'locked', 'The agent is locked. Run sf login.'))
      }

      inFlight++
      let succeeded = false
      try {
        reply(ok(req.id, await handle(req)))
        succeeded = true
      } catch (err) {
        reply(fail(req.id, err.code ?? 'error', err.message))
      } finally {
        inFlight--
        if (!stopping && succeeded && USE_OPS.has(req.op)) touch()
      }
    })

    conn.on('data', (chunk) => {
      try {
        feed(chunk)
      } catch (err) {
        reply(fail(null, err.code ?? 'bad_request', err.message))
      }
    })
  }

  async function acquireLock() {
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const handle = await open(lockFile, 'wx', 0o600)
        try {
          await handle.writeFile(lockToken)
        } finally {
          await handle.close()
        }
        return
      } catch (err) {
        if (err.code !== 'EEXIST') throw err
      }
      const held = (await readFile(lockFile, 'utf8').catch(() => '')).trim()
      const [pidText] = held.split(':')
      const pid = Number(pidText)
      // Same process, different agent (tests do this): alive. Another process:
      // alive if it still runs. Anything else was left by an agent that died.
      const alive = pid === process.pid ? held !== lockToken : pid > 0 && pidAlive(pid)
      if (alive) {
        throw new AgentError('already_running', 'An agent is already running. Run sf status or sf logout.')
      }
      await rm(lockFile, { force: true })
    }
    throw new AgentError('already_running', 'Another agent is starting at the same moment. Try again.')
  }

  async function releaseLock() {
    const held = (await readFile(lockFile, 'utf8').catch(() => '')).trim()
    // Only ever remove our own lock. A lock that belongs to a newer agent is not
    // ours to release.
    if (held === lockToken) await rm(lockFile, { force: true })
  }

  async function revokeHeld(held, everywhere, signal) {
    let access = held.access
    const expired = !held.expiresAt || now() / 1000 >= held.expiresAt - REFRESH_MARGIN_S
    if (expired && held.refresh) {
      try {
        access = (
          await refreshAccessToken({
            supabaseUrl: config.supabaseUrl,
            anonKey: config.anonKey,
            refreshToken: held.refresh,
            fetchImpl,
            signal,
          })
        ).accessToken
      } catch {
        // Fall back to the token we hold; the revoke says whether it worked.
      }
    }
    return revokeSession({
      supabaseUrl: config.supabaseUrl,
      anonKey: config.anonKey,
      accessToken: access,
      scope: everywhere ? 'global' : 'local',
      fetchImpl,
      signal,
    })
  }

  function stop(reason, { revoke = true, everywhere = false } = {}) {
    if (stopping) return stopping
    stopping = (async () => {
      clearTimeout(idleTimer)
      // Stop accepting connections. Node removes the socket file when a Unix
      // server closes; nothing here deletes that path by name, because by the
      // time a slow revoke finishes a newer agent may be listening there.
      server?.close()

      // Decryption material first, before anything touches the network, so a
      // revoke that hangs cannot keep the vault key alive while it waits. An
      // upload already running has its own copy, wiped when it returns.
      key.fill(0)
      ledgerKey.fill(0)
      const held = tokens
      tokens = { access: null, refresh: null, expiresAt: null }

      let result = { revoked: false, status: 0 }
      if (revoke) {
        // A plain timer rather than AbortSignal.timeout: that one does not keep
        // the process alive, and with the server closed nothing else might. The
        // race means a request that ignores the signal cannot hold stop() open.
        const controller = new AbortController()
        const timer = setTimeout(() => controller.abort(), stopBudgetMs)
        const outOfTime = new Promise((resolve) =>
          controller.signal.addEventListener('abort', () => resolve({ revoked: false, status: 0 }), { once: true }),
        )
        try {
          result = await Promise.race([revokeHeld(held, everywhere, controller.signal), outOfTime])
        } catch {
          // Unreachable. status stays 0, which callers report as "could not reach
          // the server", distinct from a refusal.
        } finally {
          clearTimeout(timer)
        }
      }

      await releaseLock()
      log(`agent stopped (${reason})`)
      onStop(reason, result)
      return result
    })()
    return stopping
  }

  return {
    async start() {
      await ensurePrivateDir(dirname(socket))
      await ensurePrivateDir(ledgerDir(home))
      // The lock, not the socket, decides who may start. Checking the socket and
      // then removing a stale one left a window in which two agents could both
      // conclude nothing was listening.
      await acquireLock()
      try {
        if (await socketAnswers(socket)) {
          throw new AgentError('already_running', 'An agent is already running. Run sf status or sf logout.')
        }
        // We hold the lock and nothing answered, so whatever is at this path is
        // a leftover from an agent that died.
        await rm(socket, { force: true })

        server = createServer(onConnection)
        await new Promise((resolve, reject) => {
          server.once('error', reject)
          server.listen(socket, () => {
            server.off('error', reject)
            resolve()
          })
        })
        // The directory is already 0700; this is the second lock on the same door.
        await chmod(socket, 0o600)
      } catch (err) {
        server?.close()
        await releaseLock()
        throw err
      }
      touch()
      log(`agent listening on ${socket}`)
    },
    stop,
    get stopped() {
      return Boolean(stopping)
    },
  }
}
