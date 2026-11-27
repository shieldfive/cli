import { randomUUID } from 'node:crypto'
import { lookup } from 'node:dns/promises'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { connect } from 'node:tls'
import { _internals } from './migrate.mjs'
import { networkCode, networkRequest } from './network.mjs'
import { deleteUpload, newRowBoundId, uploadFile } from './upload.mjs'
import { base64ToBytes, bytesToBase64, unwrapKeyB64 } from './uploadCrypto.mjs'

const PROBE_TIMEOUT_MS = 10_000
const MAX_CLOCK_SKEW_MS = 120_000

async function checkDns(hostname) {
  let timer
  try {
    await Promise.race([
      lookup(hostname),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(Object.assign(new Error(), { code: 'ETIMEDOUT' })), PROBE_TIMEOUT_MS)
      }),
    ])
  } finally {
    clearTimeout(timer)
  }
}

function checkTls(url) {
  return new Promise((resolve, reject) => {
    if (url.protocol !== 'https:') {
      reject(Object.assign(new Error(), { code: 'TLS_REQUIRED' }))
      return
    }
    const hostname = url.hostname.replace(/^\[|\]$/g, '')
    const socket = connect({
      host: hostname, port: Number(url.port || 443),
      servername: hostname.includes(':') || /^\d+\.\d+\.\d+\.\d+$/.test(hostname) ? undefined : hostname,
      signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
    })
    socket.once('error', reject)
    socket.once('secureConnect', () => {
      socket.destroy()
      resolve()
    })
  })
}

export async function runDoctor({
  apiBaseUrl, getSession, dnsCheck = checkDns, tlsCheck = checkTls,
}) {
  const report = []
  const pass = (label, detail = '') => report.push(`PASS ${label}${detail ? ` (${detail})` : ''}`)
  const fail = (label, detail) => report.push(`FAIL ${label} (${detail})`)
  const skip = (label) => report.push(`SKIP ${label}`)
  const started = Date.now()
  try {
    const res = await networkRequest(new URL('/api/uptime', apiBaseUrl), {
      method: 'HEAD', redirect: 'error', headers: { 'Cache-Control': 'no-cache' },
    }, 'API reachability', PROBE_TIMEOUT_MS)
    if (!res.ok) fail('API reachability', `HTTP ${res.status}`)
    else pass('API reachability', `HTTP ${res.status}`)
    // Use the midpoint so RTT doesn't appear as clock skew.
    const skew = Date.parse(res.headers.get('date')) - (started + Date.now()) / 2
    if (!Number.isFinite(skew)) fail('Clock skew', 'server Date header unavailable')
    else if (Math.abs(skew) >= MAX_CLOCK_SKEW_MS) fail('Clock skew', `${Math.round(skew / 1000)} s (server minus local)`)
    else pass('Clock skew', `${Math.round(skew / 1000)} s (server minus local)`)
  } catch (err) {
    fail('API reachability', err.networkCode ?? 'REQUEST_FAILED')
    skip('Clock skew')
  }

  let session
  try {
    session = await getSession?.()
  } catch {
    fail('Sign-in', 'run sf login and retry')
  }
  if (!session) {
    if (!report.some((line) => line.startsWith('FAIL Sign-in'))) fail('Sign-in', 'run sf login and retry')
    for (const label of ['Storage DNS', 'Storage TLS', 'Test upload', 'Delete test upload']) skip(label)
    return report
  }

  const { accessToken, rootKey } = session
  const rowId = newRowBoundId()
  const name = `ShieldFive doctor ${randomUUID()}.txt`
  let directory
  let startedUpload = false
  let host
  let step = 'Find cleanup location'
  const detail = (err) => [
    err.status ? `HTTP ${err.status}` : (err.networkCode ?? 'REQUEST_FAILED'),
    err.storageFailure && /\(RequestTimeTooSkewed, clock skew\)$/.test(err.message) ? 'clock skew' : null,
    host,
  ].filter(Boolean).join(', ')
  try {
    // Ready files can only be hard-deleted from the Bin on a vault that has one.
    const { apiJson, withRetry } = _internals
    const listing = await withRetry(() => apiJson(apiBaseUrl, accessToken, '/api/folders/tree'), { attempts: 2 })
    const bin = listing.tree?.find((folder) => folder.is_bin && !folder.parent_id)
    const folderKey = bin ? base64ToBytes(unwrapKeyB64({
      wrappingKeyB64: bytesToBase64(rootKey), wrappedKeyB64: bin.fk_wrapped, ivB64: bin.fk_iv,
    })) : null
    step = 'Prepare test file'
    directory = await mkdtemp(join(tmpdir(), 'sf-doctor-'))
    const path = join(directory, 'probe')
    await writeFile(path, 'sf doctor\n', { mode: 0o600 })
    step = 'Create upload session / get storage credentials'
    startedUpload = true
    try {
      await uploadFile({
        apiBaseUrl, accessToken, rootKey, name, path, size: 10, rowId,
        folderId: bin?.id ?? null, folderKey,
        beforeStorage: async (url) => {
          if (host !== url.host) {
            host = url.host
            try {
              await dnsCheck(url.hostname.replace(/^\[|\]$/g, ''))
              pass('Storage DNS', host)
            } catch (err) {
              fail('Storage DNS', `${networkCode(err)}, ${host}`)
            }
            try {
              await tlsCheck(url)
              pass('Storage TLS', host)
            } catch (err) {
              fail('Storage TLS', `${networkCode(err)}, ${host}`)
            }
          }
          step = 'Send storage part'
        },
        onPartUploaded: () => { step = 'Complete upload' },
      })
      pass('Test upload', `session, one part, complete, ${host}`)
    } finally {
      folderKey?.fill(0)
    }
  } catch (err) {
    if (!host) {
      skip('Storage DNS')
      skip('Storage TLS')
    }
    fail(`Test upload / ${step}`, detail(err))
  } finally {
    if (startedUpload) {
      try {
        await deleteUpload({ apiBaseUrl, accessToken, fileId: rowId })
        pass('Delete test upload')
      } catch (err) {
        fail('Delete test upload', detail(err))
      }
    } else skip('Delete test upload')
    if (directory) await rm(directory, { recursive: true, force: true }).catch(() => {})
  }
  return report
}
