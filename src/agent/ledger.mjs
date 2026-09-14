// ShieldFive CLI — the upload ledger.
//
// One JSON line per upload the agent performed:
//
//   {"v":1,"path":"/abs/path","size":48211,"mtimeMs":…,"mac":"<hex>",
//    "fileId":"…","uploadedAt":"…","device":"<uuid>"}
//
// `mac` is HMAC-SHA256 over the file's plaintext, keyed by a key derived from
// the vault root key. A plain SHA-256 would let anyone who reads this file
// confirm whether you hold a specific known document; keyed, the entries are
// unlinkable without the root key, and only an unlocked agent can compute the
// MAC of a local file to compare against them.
//
// Nothing here decides that a file is backed up by its name, path or size. A
// match on the MAC says the same bytes were uploaded once; whether they are
// still safely stored is a question for the server, asked at the moment it
// matters (see classify()).

import { createHmac, hkdfSync } from 'node:crypto'
import { createReadStream } from 'node:fs'
import { mkdir, open, readFile, stat } from 'node:fs/promises'
import { dirname, isAbsolute, join } from 'node:path'

export const LEDGER_VERSION = 1
const LEDGER_INFO = 'shieldfive/cli/ledger/v1'
export const VERIFY_BATCH = 100

/** Derive the ledger MAC key from the 32-byte vault root key. */
export function deriveLedgerKey(rootKey) {
  if (!(rootKey instanceof Uint8Array) || rootKey.length !== 32) {
    throw new Error('deriveLedgerKey needs the 32-byte root key')
  }
  return Buffer.from(hkdfSync('sha256', rootKey, Buffer.alloc(0), LEDGER_INFO, 32))
}

/** HMAC-SHA256 of a file's bytes, streamed. Returns lowercase hex. */
export function macFile(path, ledgerKey) {
  return new Promise((resolve, reject) => {
    const hmac = createHmac('sha256', ledgerKey)
    const stream = createReadStream(path)
    stream.on('error', reject)
    stream.on('data', (chunk) => hmac.update(chunk))
    stream.on('end', () => resolve(hmac.digest('hex')))
  })
}

export function ledgerPath(dir, accountId) {
  // Supabase user ids are UUIDs. Validating the shape keeps an account id from
  // ever being read as a path.
  if (typeof accountId !== 'string' || !/^[0-9a-f-]{36}$/i.test(accountId)) {
    throw new Error(`Refusing ledger for malformed account id ${JSON.stringify(accountId)}`)
  }
  return join(dir, `${accountId.toLowerCase()}.jsonl`)
}

/** Append one record and fsync it. Creates the file 0600 inside a 0700 dir. */
export async function appendEntry(file, entry) {
  await mkdir(dirname(file), { recursive: true, mode: 0o700 })
  const record = { v: LEDGER_VERSION, ...entry }
  const handle = await open(file, 'a', 0o600)
  try {
    await handle.write(JSON.stringify(record) + '\n')
    await handle.sync()
  } finally {
    await handle.close()
  }
  return record
}

/**
 * Every well-formed record, oldest first. A malformed line is counted and
 * skipped rather than failing the read, so one torn write does not hide every
 * other upload.
 */
export async function readEntries(file) {
  let raw
  try {
    raw = await readFile(file, 'utf8')
  } catch (err) {
    if (err.code === 'ENOENT') return { entries: [], malformed: 0 }
    throw err
  }

  const entries = []
  let malformed = 0
  for (const line of raw.split('\n')) {
    if (!line.trim()) continue
    try {
      const rec = JSON.parse(line)
      if (
        rec?.v === LEDGER_VERSION &&
        typeof rec.path === 'string' &&
        typeof rec.mac === 'string' &&
        /^[0-9a-f]{64}$/.test(rec.mac) &&
        typeof rec.fileId === 'string' &&
        rec.fileId
      ) {
        entries.push(rec)
      } else {
        malformed++
      }
    } catch {
      malformed++
    }
  }
  return { entries, malformed }
}

/**
 * Where each local path stands.
 *
 *   verified              the bytes on disk now were uploaded, and the server
 *                         confirms that upload is stored, ready, outside the Bin
 *                         and intact
 *   missing               the bytes were uploaded, but the server cannot confirm
 *                         it is still safely stored
 *   changed_since_upload  this path was uploaded, but the file has changed since
 *   not_in_ledger         no record of these bytes being uploaded from here
 *   unreadable            the local file could not be read
 *
 * `not_in_ledger` is not `missing`. It means this agent never uploaded these
 * bytes; the file may well be in the vault from another device.
 *
 * `verifyFileIds(ids)` must resolve to a Set (or array) of the ids the server
 * reports verified. It is called in batches of at most VERIFY_BATCH.
 */
export async function classify(paths, { entries, ledgerKey, verifyFileIds }) {
  const byMac = new Map()
  const byPath = new Map()
  for (const e of entries) {
    const macList = byMac.get(e.mac) ?? []
    macList.push(e)
    byMac.set(e.mac, macList)
    byPath.set(e.path, e) // later records win: entries are oldest first
  }

  const pending = []
  const results = []

  for (const path of paths) {
    if (typeof path !== 'string' || !isAbsolute(path)) {
      results.push({ path, state: 'unreadable', reason: 'not an absolute path' })
      continue
    }

    let st
    try {
      st = await stat(path)
    } catch (err) {
      results.push({ path, state: 'unreadable', reason: err.code ?? 'stat failed' })
      continue
    }
    if (!st.isFile()) {
      results.push({ path, state: 'unreadable', reason: 'not a regular file' })
      continue
    }

    let mac
    try {
      mac = await macFile(path, ledgerKey)
    } catch (err) {
      results.push({ path, state: 'unreadable', reason: err.code ?? 'read failed' })
      continue
    }

    const sameBytes = byMac.get(mac)
    if (sameBytes?.length) {
      // Prefer the record for this exact path; otherwise any upload of the same
      // bytes counts, because identity here is the content, not the location.
      const own = sameBytes.filter((e) => e.path === path)
      const candidates = (own.length ? own : sameBytes).map((e) => e.fileId)
      const result = { path, state: null, size: st.size, fileIds: [...new Set(candidates)] }
      if (!own.length) result.matchedPath = sameBytes[sameBytes.length - 1].path
      results.push(result)
      pending.push(result)
      continue
    }

    if (byPath.has(path)) {
      results.push({ path, state: 'changed_since_upload', size: st.size })
      continue
    }

    results.push({ path, state: 'not_in_ledger', size: st.size })
  }

  const ids = [...new Set(pending.flatMap((r) => r.fileIds))]
  const verified = new Set()
  for (let i = 0; i < ids.length; i += VERIFY_BATCH) {
    const batch = ids.slice(i, i + VERIFY_BATCH)
    const answer = await verifyFileIds(batch)
    for (const id of answer ?? []) verified.add(id)
  }

  for (const r of pending) {
    const ok = r.fileIds.find((id) => verified.has(id))
    r.state = ok ? 'verified' : 'missing'
    if (ok) r.fileId = ok
    delete r.fileIds
  }

  return results
}
