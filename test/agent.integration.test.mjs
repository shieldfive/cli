// VERIFIED (offline, real processes): `sf __agent` runs as its own process and
// separate `sf status`, `sf verify` and `sf logout` processes reach it over the
// real socket, against a local stub of the auth and verify endpoints. The unit
// tests prove the pieces; this proves they meet across process boundaries the
// way a user runs them.

import assert from 'node:assert/strict'
import { execFile, spawn } from 'node:child_process'
import { webcrypto } from 'node:crypto'
import { mkdtemp, writeFile } from 'node:fs/promises'
import { createServer } from 'node:http'
import { join } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

const CLI = fileURLToPath(new URL('../src/cli.mjs', import.meta.url))
const run = promisify(execFile)
const ACCOUNT = '3f0b2c9e-1d4a-4b6f-9c2e-7a8d5e6f1a2b'

function firstLine(stream, ms) {
  return new Promise((resolve, reject) => {
    let buf = ''
    const timer = setTimeout(() => reject(new Error(`no line within ${ms} ms`)), ms)
    stream.setEncoding('utf8')
    stream.on('data', (chunk) => {
      buf += chunk
      const nl = buf.indexOf('\n')
      if (nl !== -1) {
        clearTimeout(timer)
        resolve(buf.slice(0, nl))
      }
    })
  })
}

function exited(child, ms) {
  return new Promise((resolve, reject) => {
    if (child.exitCode !== null) return resolve(child.exitCode)
    const timer = setTimeout(() => reject(new Error(`process still running after ${ms} ms`)), ms)
    child.on('exit', (code) => {
      clearTimeout(timer)
      resolve(code)
    })
  })
}

test('the agent runs as a separate process; status, verify and logout reach it', async () => {
  const home = await mkdtemp('/tmp/sfi-home-')
  const tmp = await mkdtemp('/tmp/sfi-tmp-')
  const calls = { logout: [], verify: 0 }

  const stub = createServer((req, res) => {
    req.resume()
    req.on('end', () => {
      if (req.url.startsWith('/auth/v1/logout')) {
        calls.logout.push(req.headers.authorization)
        return res.writeHead(204).end()
      }
      if (req.url === '/api/mobile/media/verify') {
        calls.verify++
        return res.writeHead(200, { 'content-type': 'application/json' }).end('{"verified":[],"missing":[]}')
      }
      res.writeHead(404).end()
    })
  })
  await new Promise((r) => stub.listen(0, '127.0.0.1', r))
  const base = `http://127.0.0.1:${stub.address().port}`

  // HOME and TMPDIR point at scratch directories; XDG_RUNTIME_DIR is left out so
  // Linux falls back to $HOME/.shieldfive/run. Nothing else is inherited.
  const env = { PATH: process.env.PATH, HOME: home, TMPDIR: tmp }

  const agent = spawn(process.execPath, [CLI, '__agent'], { env, stdio: ['pipe', 'pipe', 'pipe'] })
  let agentErr = ''
  agent.stderr.setEncoding('utf8')
  agent.stderr.on('data', (c) => {
    agentErr += c
  })

  try {
    agent.stdin.end(
      JSON.stringify({
        session: {
          accessToken: 'at-1',
          refreshToken: 'rt-1',
          expiresAt: Math.floor(Date.now() / 1000) + 3600,
          userId: ACCOUNT,
        },
        rootKey: Buffer.from(webcrypto.getRandomValues(new Uint8Array(32))).toString('base64'),
        config: { apiBaseUrl: base, supabaseUrl: base, anonKey: 'anon' },
      }),
    )
    const ready = JSON.parse(await firstLine(agent.stdout, 10_000).catch((e) => {
      throw new Error(`${e.message}; agent stderr: ${agentErr}`)
    }))
    assert.equal(ready.ready, true)

    const status = await run(process.execPath, [CLI, 'status'], { env })
    assert.match(status.stdout, new RegExp(`Logged in \\(account ${ACCOUNT}\\)`))

    const doc = join(home, 'doc.txt')
    await writeFile(doc, 'never uploaded')
    const verify = await run(process.execPath, [CLI, 'verify', doc], { env }).catch((e) => e)
    assert.equal(verify.code, 2, 'verify exits non-zero unless every file is confirmed')
    assert.match(verify.stdout, /no upload record/)
    assert.equal(calls.verify, 0, 'nothing in the ledger, so the server is not asked')

    const logout = await run(process.execPath, [CLI, 'logout'], { env })
    assert.match(logout.stdout, /revoked on the server/)
    assert.deepEqual(calls.logout, ['Bearer at-1'])

    assert.equal(await exited(agent, 5_000), 0)
    const after = await run(process.execPath, [CLI, 'status'], { env })
    assert.match(after.stdout, /Not logged in/)
  } finally {
    agent.kill()
    stub.close()
  }
})
