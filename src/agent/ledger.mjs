// ShieldFive CLI — the upload ledger.
//
// One JSON line per upload the agent performed:
//
//   {"v":1,"path":"/abs/path","size":48211,"mtimeMs":…,"mac":"<hex>",
//    "fileId":"…","uploadedAt":"…","device":"<uuid>","tag":"<hex>"}
//
// `mac` is HMAC-SHA256 over exactly the plaintext bytes that were encrypted and
// uploaded, keyed by a key derived from the vault root key. A plain SHA-256
// would let anyone who reads this file confirm whether you hold a specific
// known document; keyed, the entries are unlinkable without the root key.
//
// `tag` is HMAC-SHA256 over the record's other fields under the same key. The
// ledger is an ordinary file the user's processes can write, so without it a
// forged line naming a missing file's MAC and some real fileId would make that
// file report as backed up. Records whose tag does not verify are dropped.
//
// Nothing here decides that a file is backed up by its name, path or size. A
// match on the MAC says those exact bytes were uploaded; whether they are still
// safely stored is a question for the server, asked at the moment it matters
// (see classify()).

import { createHmac, hkdfSync, timingSafeEqual } from 'node:crypto'
import { createReadStream } from 'node:fs'
import { mkdir, open, readFile, stat } from 'node:fs/promises'
import { dirname, isAbsolute, join } from 'node:path'

export const LEDGER_VERSION = 1
const LEDGER_INFO = 'shieldfive/cli/ledger/v1'
const TAGGED_FIELDS = ['v', 'path', 'size', 'mtimeMs', 'mac', 'fileId', 'uploadedAt', 'device']
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

function tagFor(ledgerKey, record) {
  const fields = TAGGED_FIELDS.map((f) => record[f] ?? null)
  return createHmac('sha256', ledgerKey).update(JSON.stringify(fields)).digest('hex')
}

export function ledgerPath(dir, accountId) {
  // Supabase user ids are UUIDs. Validating the shape keeps an account id from
  // ever being read as a path.
  if (typeof accountId !== 'string' || !/^[0-9a-f-]{36}$/i.test(accountId)) {
    throw new Error(`Refusing ledger for malformed account id ${JSON.stringify(accountId)}`)
  }
  return join(dir, `${accountId.toLowerCase()}.jsonl`)
}

/** Tag, append and fsync one record. Creates the file 0600 inside a 0700 dir. */
export async function appendEntry(file, entry, { ledgerKey } = {}) {
  if (!ledgerKey) throw new Error('appendEntry needs the ledger key to tag the record')

  // Build and tag the record before the first await. The agent overwrites the
  // key on logout, and a tag computed after that would be a tag under zeros.
  const record = { v: LEDGER_VERSION, ...entry }
  record.tag = tagFor(ledgerKey, record)
  const line = JSON.stringify(record) + '\n'

  await mkdir(dirname(file), { recursive: true, mode: 0o700 })
  const handle = await open(file, 'a+', 0o600)
  try {
    // If a previous write was torn and left no trailing newline, start on a new
    // line. Otherwise this record would be glued to the broken one and both
    // would be discarded as malformed.
    const { size } = await handle.stat()
    let prefix = ''
    if (size > 0) {
      const { buffer } = await handle.read(Buffer.alloc(1), 0, 1, size - 1)
      if (buffer[0] !== 0x0a) prefix = '\n'
    }
    await handle.write(prefix + line)
    await handle.sync()
  } finally {
    await handle.close()
  }
  return record
}

/**
 * Every well-formed, correctly tagged record, oldest first.
 *
 * A malformed line or a record whose tag does not verify is counted and
 * skipped rather than failing the read, so one torn write or one forged line
 * does not hide every other upload.
 */
export async function readEntries(file, { ledgerKey } = {}) {
  if (!ledgerKey) throw new Error('readEntries needs the ledger key to check record tags')

  let raw
  try {
    raw = await readFile(file, 'utf8')
  } catch (err) {
    if (err.code === 'ENOENT') return { entries: [], malformed: 0, unauthenticated: 0 }
    throw err
  }

  const entries = []
  let malformed = 0
  let unauthenticated = 0
  for (const line of raw.split('\n')) {
    if (!line.trim()) continue
    let rec
    try {
      rec = JSON.parse(line)
    } catch {
      malformed++
      continue
    }
    const wellFormed =
      rec?.v === LEDGER_VERSION &&
      typeof rec.path === 'string' &&
      typeof rec.mac === 'string' &&
      /^[0-9a-f]{64}$/.test(rec.mac) &&
      typeof rec.fileId === 'string' &&
      rec.fileId &&
      typeof rec.tag === 'string' &&
      /^[0-9a-f]{64}$/.test(rec.tag)
    if (!wellFormed) {
      malformed++
      continue
    }
    const expected = Buffer.from(tagFor(ledgerKey, rec), 'hex')
    if (!timingSafeEqual(expected, Buffer.from(rec.tag, 'hex'))) {
      unauthenticated++
      continue
    }
    entries.push(rec)
  }
  return { entries, malformed, unauthenticated }
}

/**
 * Where each local path stands.
 *
 *   verified              the bytes on disk now are bytes that were uploaded,
 *                         and the server confirms that upload is stored, ready,
 *                         outside the Bin and intact
 *   missing               the bytes were uploaded, but the server cannot confirm
 *                         it is still safely stored
 *   changed_since_upload  this path was uploaded, but the file has changed since
 *   not_in_ledger         no record of these bytes being uploaded from here
 *   unreadable            the local file could not be read
 *
 * `not_in_ledger` is not `missing`. It means this agent never uploaded these
 * bytes; the file may well be in the vault from another device.
 *
 * When `device` is given, only records made on that device count.
 *
 * `verifyFileIds(ids)` must resolve to the ids the server reports verified. It
 * is called in batches of at most VERIFY_BATCH, and an id in an answer only
 * counts if that batch asked about it.
 */
export async function classify(paths, { entries, ledgerKey, verifyFileIds, device }) {
  const usable = device ? entries.filter((e) => e.device === device) : entries

  const byMac = new Map()
  const byPath = new Map()
  for (const e of usable) {
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
    const asked = new Set(batch)
    const answer = await verifyFileIds(batch)
    for (const id of answer ?? []) {
      // An id the server volunteered without being asked in this batch is not
      // an answer to this question. On a check that gates deletion, that must
      // fail closed.
      if (asked.has(id)) verified.add(id)
    }
  }

  for (const r of pending) {
    const ok = r.fileIds.find((id) => verified.has(id))
    r.state = ok ? 'verified' : 'missing'
    if (ok) r.fileId = ok
    delete r.fileIds
  }

  return results
}
